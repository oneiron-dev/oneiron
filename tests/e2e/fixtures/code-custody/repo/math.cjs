"use strict";

function add(a, b) {
  if (!Number.isFinite(a) || !Number.isFinite(b)) {
    throw new TypeError("finite numbers required");
  }
  return a + b;
}

function increment(value) {
  return add(value, 1);
}

module.exports = { add, increment };
