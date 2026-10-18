"use strict";

const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { createReadStream } = require("node:fs");
const { join } = require("node:path");
const recipe = require("./large-blob.json");

async function build() {
  const hash = createHash("sha256");
  let size = 0;
  for await (const bytes of createReadStream(join(__dirname, recipe.repository_path))) {
    size += bytes.length;
    hash.update(bytes);
  }
  const digest = hash.digest("hex");
  assert.equal(size, recipe.byte_length);
  assert.equal(digest, recipe.sha256);
  require("./main.cjs");
  process.stdout.write("asset:" + digest + "\n");
}

build().catch(() => {
  process.stderr.write("mirror build failed\n");
  process.exitCode = 1;
});
