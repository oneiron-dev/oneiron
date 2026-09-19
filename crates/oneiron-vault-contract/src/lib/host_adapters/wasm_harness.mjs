// A real WebAssembly guest with exactly one capability import: bounded sleep.
// Fixture secrets and limits are synthetic. No WASI, filesystem or exit imports.
import { createInterface } from "node:readline";
const text = value => [...new TextEncoder().encode(value)];
const name = value => [text(value).length, ...text(value)];
const section = (id, bytes) => [id, bytes.length, ...bytes];
const exports = ["listener", "ready", "secret", "on_stop", "limits", "idle"];
const bodies = [
  [0, 0x41, 42, 0x0b],
  [0, 0x41, 1, 0x24, 0, 0x41, 1, 0x0b],
  [0, 0x41, 17, 0x0b],
  [0, 0x41, 0, 0x24, 0, 0x41, 0, 0x0b],
  [0, 0x41, 32, 0x0b],
  [0, 0x20, 0, 0x10, 0, 0x23, 0, 0x0b]
];
const bytes = new Uint8Array([
  0,97,115,109,1,0,0,0,
  ...section(1,[3,0x60,0,1,0x7f,0x60,1,0x7f,0,0x60,1,0x7f,1,0x7f]),
  ...section(2,[1,...name("host"),...name("sleep"),0,1]),
  ...section(3,[6,0,0,0,0,0,2]),
  ...section(6,[1,0x7f,1,0x41,0,0x0b]),
  ...section(7,[6,...exports.flatMap((value,index)=>[...name(value),0,index+1])]),
  ...section(10,[6,...bodies.flatMap(body=>[body.length,...body])])
]);
const module = new WebAssembly.Module(bytes);
const instance = new WebAssembly.Instance(module, {host:{sleep(ms){
  if (!Number.isInteger(ms) || ms < 0 || ms > 100) throw new Error("sleep outside fixture bound");
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,ms);
}}});
for await (const line of createInterface({input:process.stdin})) {
  const request=JSON.parse(line);
  if (!exports.includes(request.verb)) throw new Error("unknown capability");
  const value=instance.exports[request.verb](request.ms ?? 0);
  process.stdout.write(JSON.stringify({value})+"\n");
}
