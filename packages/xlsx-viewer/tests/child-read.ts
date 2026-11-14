/**
 * Starts a child read ({@link ./read-in-child.ts}) of one crafted package and
 * gives its answer, or how the child ended without one.
 */
import type { CraftedKind } from "./crafted-packages";

/** How long a child may read before its test counts the read as one that never ends. */
export const CHILD_LIMIT_MS = 30_000;
/** A child read test's own limit: the child's, then the time to start it and build its package. */
export const TEST_LIMIT_MS = 90_000;

/** The door a child reads through: sheet S1, or the workbook outline. */
export type ChildDoor = "sheet" | "outline";

/** What a child read gave: its answer, and how long the read itself took when it answered. */
export interface ChildRead {
  readonly answer: unknown;
  readonly readMs?: number;
}

export function readInChild(kind: CraftedKind, door: ChildDoor = "sheet"): ChildRead {
  const run = Bun.spawnSync({
    cmd: [process.execPath, `${import.meta.dir}/read-in-child.ts`, kind, door],
    stdout: "pipe",
    stderr: "pipe",
    timeout: CHILD_LIMIT_MS,
  });
  if ((run as { exitedDueToTimeout?: boolean }).exitedDueToTimeout) {
    return { answer: { unfinished: `still reading after ${CHILD_LIMIT_MS / 1000} s` } };
  }
  if (!run.success) {
    return { answer: { ended: run.signalCode ?? run.exitCode, stderr: run.stderr.toString().slice(-400) } };
  }
  return JSON.parse(run.stdout.toString().trim().split("\n").at(-1)!) as ChildRead;
}
