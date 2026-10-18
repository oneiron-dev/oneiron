import { afterAll, test } from "bun:test";
import type { FacadeInput, FacadeResult, FacadeVerb } from "@oneiron/client";
import { defineFile } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 2 });
afterAll(suite.flush);

/*
 * Code execution and custody, in plan order. Complete-flow TODOs: no passing
 * substitute for an unavailable setup or mutation door. suite.todo registers
 * Bun test.todo and the shared runner's mandatory BLOCKED report row.
 *
 * Binding read: main cf8d4ce473ddffb6bf278f11263ae0cf84461117, this worktree's
 * HEAD and origin/main. code-custody-scenarios pins the catalog, generated SDKs,
 * OpenAPI assembly, CLI, Git/LFS routes, canon and registry bytes read here.
 * The shared harness's older binding pin is left alone.
 *
 * Types below are CANON DESIGN NOTES, not new SDK methods or proposed URLs.
 * PublicCall refers only to EXISTING generated HTTP/SDK DTOs. Canon specifies
 * semantics but does not pin wire spellings for the missing operations. G01
 * requires their typed HTTP and SDK calls before activation. Do not cast verbs,
 * use execute_code, structural.put, kv.put, batch or Rust/private vault seeding
 * to manufacture repo, lease, queue, cache, publication or conflict records.
 * /api/lease/revoke revokes a device binding, not a checkout lease.
 *
 * Activation uses EngineFixture.start({ id, profile }) for a fresh authenticated
 * vault per ID and loadFixtures() for this fragment. A second account/vault in
 * 06/07 uses peers: 1 and explicit public policy; it gains no automatic grants.
 * Every generated reference comes from public setup; fixture labels are not
 * entity ids. Use the fixture's real paired HTTP/CLI clients, awaitReceipt and
 * owned runProcess/ManagedProcess for Linux git/node clients. All helpers and
 * servers share this file's two slots. Do not build/install/download in a flow.
 *
 * Observe wall-clock lease expiry via public state, receipts and bounded
 * observation, never a private clock/tick or fixed sleep. Zero automatic
 * mutation retries; the explicit settlement replay in 02 is the behavior under
 * test. kill() follows the full public publication ACK, never a log message.
 * Credentials go through private env/stdin; a git transport needs a holder proof
 * for EACH request, not one static extraHeader reused across an exchange.
 * No upstream value belongs in checkout files, remotes, git config or argv.
 *
 * Independent fixtures retain all eight names, steps and expected facts, a tiny
 * source tree and real contract-check command, and a >16 MiB byte/digest recipe.
 * Recipes are data, not fabricated server records. The shared manifest loader
 * checks these files even while the full flows remain blocked. No helper is
 * added to stand in for a missing production door.
 */
type Ref = string;
type Sha256 = string;
type PublicCall<V extends FacadeVerb> = {
  request: FacadeInput<V>;
  result: FacadeResult<V>;
};
type VersionedFile = {
  document: Ref;
  version: Ref;
  path: string;
  text_sha256: Sha256;
};
type TestedTree = {
  revision: Ref;
  parent: Ref | null;
  file_frontiers: VersionedFile[];
  provenance_receipt: Ref;
};
type LeaseEpoch = { checkout: Ref; holder: Ref; epoch: number };
type ActionDigest = { hash: Sha256; size_bytes: number };

// CODE-CUSTODY-01 — Repository scope and pointer ingest should work.
// OF-322 / OF-354 / OF-316; ARCH-0050 #tested-pointer, R1/R2/R3.
// Register the committed fixture folder plus editable whitelist, then capture
// its bytes and ingest-time symbols. The actual git commit comes from the real
// client, not a made-up 40-hex constant. Repo scope is explicit membership on a
// CODE artifact, not an epistemic WORLD row or an ambient disk-path grant.
// Query increment's calls/import neighbors at the pinned snapshot: add is its
// callee and main.cjs references increment. Require repo+version+file/span
// citations and compare text/digests to the fixture, not to another engine read.
// Mutate math.cjs on disk to subtraction; repeat pinned read AND symbol search.
// Both must retain the original addition and citations. A new capture may show
// the dirty bytes, but must not mutate the old version. A scope-excluded actor
// gets no code text, result or count hint. Ordinary vault.recall is not a
// substitute for typed snapshot/symbol navigation.
type CodeCustody01 = {
  register: {
    pointer: { local_folder: string; commit: string };
    editable_whitelist: string[];
  };
  registered: { code_artifact: Ref; scope: Ref; receipt: Ref };
  capture: { repo: Ref };
  snapshot: { repo: Ref; snapshot: Ref; files: VersionedFile[]; receipt: Ref };
  neighbors: { repo: Ref; snapshot: Ref; symbol: Ref; relations: ("calls" | "imports" | "refs")[] };
  found: { symbol: Ref; relation: "calls" | "imports" | "refs"; citation: VersionedFile }[];
  read: { repo: Ref; snapshot: Ref; path: string };
  pinned: { file: VersionedFile; content: string };
};
type CodeCustody01Current = PublicCall<"vault.code.blame">;
suite.todo(test, "CODE-CUSTODY-01", "waits on typed repo pointer registration, snapshot capture, symbol-neighbor search and pinned source read");

// CODE-CUSTODY-02 — Lease expiry prevents stale publication should work.
// OF-424 / OF-425; ARCH-0068 RC1/RC2/RC4; ARCH-0040 #mcp-actor-ceilings.
// Publicly create two authorized holders; pairActor only pairs existing ones.
// A takes the declared-idempotent build/verify checkout with a short PUBLIC
// lease. Observe expiry, B's reclaim and a strictly newer epoch. A's old ticket
// must fail at publication/settlement even if A still has general write scope;
// no head move or applied result may follow. B publishes and settles the same
// deterministic candidate twice: identical receipt, exactly one promotion.
// Repeat reclamation on an effect-task: expiry alone does not auto-claim for B;
// explicit authorized takeover is required. Dirty/uncertain teardown retains
// the checkout; only a pushed-head receipt plus lease occupancy permits cleanup.
// Existing /git/lease/{lease}/{repo}/... routes accept id.epoch tickets and
// still authenticate the registered actor. They do not create/renew/reclaim
// a lease or expose consume-once settlement. tasks.accept's attempt fencing
// is not evidence of checkout epoch fencing.
type CodeCustody02 = {
  lease: { repo: Ref; task: Ref; holder: Ref; ttl_seconds: number; declared_idempotent: boolean };
  granted: LeaseEpoch & { expires_at: number; ticket: Ref; receipt: Ref };
  reclaim: { checkout: Ref; expired_epoch: number; holder: Ref };
  reclaimed: LeaseEpoch & { receipt: Ref };
  publish: LeaseEpoch & { candidate: Ref };
  settle: LeaseEpoch & { candidate: Ref; action: "select" | "apply" | "release" | "discard" };
  settlement: { candidate: Ref; receipt: Ref; action: "select" | "apply" | "release" | "discard" };
  teardown: { checkout: Ref; pushed_head_receipt: Ref | null };
};
type CodeCustody02Current = PublicCall<"tasks.accept">;
suite.todo(test, "CODE-CUSTODY-02", "waits on typed checkout lease claim/expiry/reclaim, epoch-fenced publication and consume-once settlement");

// CODE-CUSTODY-03 — Symbol overlap schedules rather than drops should work.
// OF-480; ARCH-0050 #many-agents and #tested-pointer.
// Lease add for proposal A. Submit A, another add proposal B, and independent
// label proposal C; A/B edit different spans of the SAME symbol so scheduling
// need not create an unavoidable textual conflict. Every submission remains
// addressable. B is behind the leased proposal, not refused/discarded; C can
// complete while B waits. Inspect a public queue observation proving both
// facts, release the lease, then await all three receipted completions. Assert
// order constraints, not magic queue positions or fairness latency. Advisory
// ops and binding queue order must remain distinct. The grant controls write
// authority; a symbol lease never grants approval or authority to erase work.
type CodeCustody03 = {
  lease: { repo: Ref; task: Ref; symbols: Ref[]; ttl_seconds: number };
  submit: { repo: Ref; proposal: Ref; base: Ref; touched_symbols: Ref[] };
  admitted: { proposal: Ref; queue_entry: Ref; receipt: Ref };
  queue: {
    entries: { proposal: Ref; state: "waiting" | "running" | "landed"; waits_for: Ref[] }[];
    completions: { proposal: Ref; receipt: Ref }[];
  };
  release: { lease: Ref; epoch: number };
};
suite.todo(test, "CODE-CUSTODY-03", "waits on typed symbol leases, code proposal submission, queue observation and lease release");

// CODE-CUSTODY-04 — Merge queue isolates failed batch should work.
// OF-481 / OF-482; ARCH-0050 #tested-pointer and #many-agents.
// Start from the fixture's checked baseline. Submit good-math, bad-api and
// good-label in one batching window declared through PUBLIC queue policy.
// Execute node contract-check.cjs through the REAL checker/sandbox, never a
// provider success, caller-supplied verdict, precomputed exit or pretend job.
// The independent JSON contract checks public exports, numeric behavior,
// exception class and exact CLI bytes. bad-api removes increment; a command
// failure and the missing public name must be retained as evidence. The queue
// bisects the failed batch, keeps all proposal identities and last-green, and
// lands the valid subset under declared policy. Head is fast-tested; green is
// slow-tested: inspect both and their checker receipts, never accept a failing
// candidate as either proven green. Repair the retained bad proposal, rerun the
// same command, then observe green advance with the new passing receipt. Prior
// failure evidence survives. Contract breakage routes to the required review.
type CodeCustody04 = {
  configure: { repo: Ref; fast_check_argv: string[]; slow_check_argv: string[]; batch_policy: Ref };
  enqueue: { repo: Ref; proposals: Ref[]; base_green: Ref };
  observation: {
    head: TestedTree;
    green: TestedTree;
    batches: { proposals: Ref[]; children: Ref[]; check_receipts: Ref[] }[];
    checks: { receipt: Ref; argv: string[]; exit_code: number; evidence: Ref[] }[];
    retained_failures: { proposal: Ref; check_receipts: Ref[] }[];
  };
  repair: { proposal: Ref; replacement_fork: Ref };
};
type CodeCustody04Current = {
  proposal: PublicCall<"vault.code.proposal_view">;
  trees: PublicCall<"vault.code.repo_diff">;
};
suite.todo(test, "CODE-CUSTODY-04", "waits on typed speculative merge-queue submission/policy, real checker execution and head/green/bisection observation");

// CODE-CUSTODY-05 — Git export and crash-safe origin publication should work.
// OF-429 / OF-484; ARCH-0050 #tested-pointer; ARCH-0068 RA1/RA2/RA3/RC4.
// Import/edit the fixture as file documents, check it, commit its tested
// frontier and export via the real origin. Clone with stock git smart-HTTP;
// checkout bytes and run the contract without hidden vault/private source.
// Push the next fixture change through the authenticated credential door.
// Require the complete per-ref successful receive-pack status and public
// publication receipt BEFORE engine.kill(); HTTP 200 or 'unpack ok' alone is
// insufficient. restart() uses the SAME build/vault. A fresh clone must contain
// every acknowledged ref, checkout exact fixture bytes and retain provenance
// linking the commit to its tested file frontiers. Never force a publication
// result or seed a bare repo under the vault. Scan only the owned checkout's
// remotes/config/files for generated upstream credentials (redactor.add first).
// A lease redemption slip may exist; the upstream secret value must not.
// Existing HTTP: /git/{repo}/{info/refs,git-upload-pack,git-receive-pack}
// and matching /git/lease/{lease}/{repo}/...; GET info/refs uses exactly one
// service=git-upload-pack or service=git-receive-pack. These are real routes,
// not absent doors. They do not register an origin or export a document-backed
// tested tree. CLI provenance reads linkage; it does not create that tree.
type CodeCustody05 = {
  commit: { repo: Ref; tested: Ref; parent: Ref | null; file_frontiers: VersionedFile[] };
  committed: TestedTree;
  export: { repo: Ref; revision: Ref };
  exported: { revision: Ref; git_commit: string; remote_url: string; receipt: Ref };
  publication: { repo: Ref; ref_name: string; git_commit: string; provenance_receipt: Ref; acknowledged: boolean };
};
suite.todo(test, "CODE-CUSTODY-05", "waits on typed document-backed tested-tree commit/git export, origin registration and checkout credential-door binding");

// CODE-CUSTODY-06 — LFS large blob fidelity and deletion should work.
// OF-430 / OF-468; ARCH-0068 RA1/RC2; ARCH-0078 #contract.
// Materialize the pinned byte recipe (>16 MiB), independently hash the file,
// then create TWO artifact owners of those bytes through public calls. Upload
// using LFS basic batch -> PUT -> verify and download; compare byte count and
// SHA-256 with the fixture's digest, not the echoed oid or internal BLAKE3 ids.
// Publish the build-required asset and pointer in the repo/LFS export, mirror
// it with a real client, disconnect the original origin, and verify the mirror
// alone can clone/smudge and hash it. No private blob path or hidden byte read.
// Erase-preview A must identify B as a surviving holder/shared-chunk owner.
// Confirm A with its preview_digest and also_same_bytes:false; A disappears,
// but B's old version and fresh LFS download still yield the exact digest.
// Same digest in another vault is NOT a vault-global existence/access grant:
// an unauthorized fetch cannot disclose the first vault's bytes. Do not assert
// different cross-vault chunk hashes or a physical chunk count: dedup is scoped
// authority/lifecycle, not a promise that content hashes differ by tenant.
// Existing LFS typed wire shapes are retained here. Artifact version and erase
// calls already exist; the origin/mirror setup is the blocking prerequisite.
type LfsObject = { oid: Sha256; size: number };
type LfsBatchRequest = { operation: "upload" | "download"; transfers: ["basic"]; objects: LfsObject[] };
type LfsBatchResponse = {
  transfer: "basic";
  objects: (LfsObject & {
    authenticated: boolean;
    actions?: Partial<Record<"upload" | "download" | "verify", { href: string }>>;
    error?: { code: number; message: string };
  })[];
};
type CodeCustody06 = {
  batch: LfsBatchRequest;
  batch_result: LfsBatchResponse;
  upload_result: LfsObject;
  verify: LfsObject;
  verified: LfsObject & { ok: boolean };
  owners: [Ref, Ref];
  mirror: { repo: Ref; exported_revision: Ref; build_required_paths: string[] };
};
type CodeCustody06Current = {
  create: PublicCall<"vault.artifacts.put">;
  append: PublicCall<"vault.artifacts.append">;
  read: PublicCall<"vault.artifacts.read">;
  erase_preview: PublicCall<"vault.records.erase_preview">;
  erase_confirm: PublicCall<"vault.records.erase_confirm">;
};
suite.todo(test, "CODE-CUSTODY-06", "waits on typed origin/repo registration and build-required LFS mirror publication setup");

// CODE-CUSTODY-07 — Working views and cache isolate authority should work.
// OF-428 / OF-483; ARCH-0068 RC7; ARCH-0069 #handles and S7 exhaust taint.
// Publicly materialize V1/V2 at the same last-green tree for one account. Run
// the tiny fixture command, pin its independently computed REAPI action digest
// and immutable expected output. V2 reuses that authorized entry with receipt
// provenance, not a second write or a magic wall-clock speed claim. Edit add in
// V1: V2 and the original version retain addition; a changed input makes a new
// action key. Do not accept hardlink edits leaking through to another view.
// An independently paired other-account vault requests the SAME action key;
// denial/miss reveals no bytes or metadata from the first account. Give that
// account explicit authority to run its own cold build: it computes its own
// output, not evidence of a shared authorized cache hit. Public scope membership
// alone never transfers an account's cache or secret-consuming exhaust.
// A declared secret-consuming build entry stays generation-tainted. After
// rotation the old generation cannot be published/exported/reused as clean;
// no secret value or secret-derived sentinel crosses to the other account.
// This proves account-local reuse only, not a host-wide cache deployment.
type CodeCustody07 = {
  materialize: { repo: Ref; tested: Ref; account: Ref };
  view: { view: Ref; base: Ref; files: VersionedFile[]; receipt: Ref };
  build: { view: Ref; argv: string[]; action_digest: ActionDigest };
  cache_read: { account: Ref; action_digest: ActionDigest };
  entry: {
    action_digest: ActionDigest;
    output_sha256: Sha256;
    account: Ref;
    secret_taint_refs: { secret_ref: Ref; rotation_generation: number }[];
    receipt: Ref;
  };
  reuse: { state: "hit" | "miss" | "denied"; entry?: Ref; receipt: Ref };
};
suite.todo(test, "CODE-CUSTODY-07", "waits on typed linked working-view materialization and account/action/secret-fenced build-cache execution and reuse");

// CODE-CUSTODY-08 — Merge conflict becomes reviewable work should work.
// OF-486; ARCH-0050 R7/#many-agents; ARCH-0067 #tasks; ARCH-0078 #contract.
// Fork two behavior-preserving but textually incompatible changes to add's
// return span from the SAME tested base. Both proposals remain addressable;
// a real overlap stores base, both sides and paths/spans as a typed conflict,
// and creates a reconciliation TASK linked to them. No silent last-writer
// winner, branch loss or source-erasing marker replacement is a resolution.
// Inspect the task's assignee, typed brief and outcome link over public reads.
// An authorized independent resolver accepts the task and proposes the fixture
// resolution. The proposers/their descendants may not self-approve it. Land
// through the normal gate/queue with the real contract checker, then follow
// the settlement receipt and final lineage back to BOTH proposals and the
// original conflict/task. Re-read after restart to prove it remains history.
// tasks.create/accept/update and vault.code.proposal_view already exist; they
// cannot fabricate a conflict, its reconciliation link or code settlement.
type CodeCustody08 = {
  proposals: { repo: Ref; base: Ref; fork: Ref; touched_symbols: Ref[] }[];
  conflict: { conflict: Ref; repo: Ref; base: Ref; left: Ref; right: Ref; paths: string[]; task: Ref };
  reconcile: { conflict: Ref; task: Ref; resolution_fork: Ref };
  settled: {
    resolution: Ref;
    receipt: Ref;
    actor: Ref;
    parents: Ref[];
    conflict: Ref;
    task: Ref;
    tested: Ref;
  };
};
type CodeCustody08Current = {
  task: PublicCall<"tasks.create">;
  accept: PublicCall<"tasks.accept">;
  update: PublicCall<"tasks.update">;
  proposal: PublicCall<"vault.code.proposal_view">;
};
suite.todo(test, "CODE-CUSTODY-08", "waits on typed code proposal/conflict creation, reconciliation-task linkage and authorized receipted resolution");
