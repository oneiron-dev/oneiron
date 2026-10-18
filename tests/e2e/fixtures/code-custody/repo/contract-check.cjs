"use strict";

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const contract = require("./contract.json");
const math = require("./math.cjs");

assert.deepEqual(Object.keys(math).sort(), contract.public_symbols);
for (const example of contract.numeric_examples) {
  assert.equal(math[example.symbol](...example.args), example.result);
}
assert.throws(() => math.add("2", 3), { name: contract.invalid_input_error });
const stdout = execFileSync(process.execPath, ["main.cjs"], {
  cwd: __dirname,
  encoding: "utf8",
});
assert.equal(stdout, contract.cli_stdout);
