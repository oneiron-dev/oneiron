"use strict";

const { increment } = require("./math.cjs");
const { label } = require("./label.cjs");
process.stdout.write(label(increment(3)) + "\n");
