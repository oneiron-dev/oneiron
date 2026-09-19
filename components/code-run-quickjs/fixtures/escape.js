const absent = [typeof process, typeof require, typeof fetch, typeof Deno, typeof std, typeof os];
let moduleRefused = false;
try { await import("std"); } catch (_) { moduleRefused = true; }
let readRefused = false;
try { await sandbox.fs.read_file("/etc/passwd"); } catch (_) { readRefused = true; }
let pathRefused = false;
try { writeOutput("/mnt/outputs/../escape", [1]); } catch (_) { pathRefused = true; }
const indirect = Function("return typeof process")();
finish({absent, moduleRefused, readRefused, pathRefused, indirect});
