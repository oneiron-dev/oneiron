#!/usr/bin/env node
/**
 * Proves the README's quickstarts are the files that actually run.
 *
 * Documentation drift is not a documentation problem — a quickstart that no
 * longer executes is a broken product with a passing test suite. So the README
 * does not paraphrase the quickstart files; it contains them byte-for-byte
 * between explicit markers, and this check fails the build when it stops.
 *
 * Marker grammar, in the README:
 *
 *     <!-- snippet:quickstart/node.mjs -->
 *     ```js
 *     ...the file, exactly...
 *     ```
 *     <!-- /snippet -->
 */

import { readFileSync } from "node:fs"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const readmePath = join(packageRoot, "README.md")
const readme = readFileSync(readmePath, "utf8")

const SNIPPET = /<!-- snippet:(?<path>[^\s]+) -->\r?\n```[a-z]*\r?\n(?<body>[\s\S]*?)```\r?\n<!-- \/snippet -->/g

const failures = []
let found = 0

for (const match of readme.matchAll(SNIPPET)) {
  const { path, body } = match.groups
  found += 1
  let expected
  try {
    expected = readFileSync(join(packageRoot, path), "utf8")
  } catch (error) {
    failures.push(`${path}: cannot read the snippet source (${error.message})`)
    continue
  }
  if (body !== expected) {
    failures.push(
      `${path}: the README block and the file differ. ` +
        `Copy the file into the README block verbatim, or update the file.`,
    )
  }
}

// A README that lost its markers would otherwise pass this check by having
// nothing to compare, which is the one failure mode a snippet checker must not
// have.
const REQUIRED = ["quickstart/node.mjs", "quickstart/python.py"]
for (const required of REQUIRED) {
  if (!readme.includes(`<!-- snippet:${required} -->`)) {
    failures.push(`${required}: the README is missing this snippet marker entirely`)
  }
}

if (failures.length > 0) {
  console.error("README snippet identity check FAILED:")
  for (const failure of failures) console.error(`  - ${failure}`)
  process.exit(1)
}

console.log(`README snippet identity check OK (${found} snippets)`)
