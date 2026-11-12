/** A loopback relay between a device peer and its home, for sync-link faults. Linux-only.
 *
 * It relays TCP byte for byte, so plain HTTP (pairing-link creation, pin fetch, redeem, checkpoint
 * reads, renewal) and every WebSocket upgrade pass unchanged in both directions, including the
 * device's authorization, x-oneiron-binding and x-oneiron-machine headers and the home's
 * x-oneiron-home-machine proof on the 101 answer. After an upgrade the relay reads WebSocket frames
 * and acts on whole data messages only: a binary or text message, with its continuation frames, is
 * one unit; control frames (close, ping, pong) always pass at once and are never counted. Frames
 * are forwarded as the sender framed and masked them; nothing is decoded, decompressed or re-signed.
 *
 * Controls act on the next messages in one direction: drop(n), duplicate(n) (each of the next n is
 * sent twice), hold() then release({order}) (fifo or reverse). cut() closes every relayed WebSocket
 * and answers new upgrades 503 until heal(); plain HTTP keeps passing. Counters are per direction:
 * `seen` counts whole messages that arrived, `forwarded` counts messages sent on (a duplicate counts
 * twice), `dropped`, `duplicated` (extra sends) and `held` (currently held). awaitSeen is a barrier
 * on `seen`, never a sleep. Counters say what the relay did, never that sync converged.
 */
import { connect, createServer, type Server, type Socket } from "node:net";
import { LIMITS, ownResource, withDeadline, assertFlowActive } from "./run.ts";

export type SyncLinkDirection = "to_home" | "to_device";
export interface SyncLinkCounts {
  readonly seen: number; readonly forwarded: number; readonly dropped: number;
  readonly duplicated: number; readonly held: number;
}
interface DirectionState {
  seen: number; forwarded: number; dropped: number; duplicated: number;
  dropNext: number; duplicateNext: number; holding: boolean;
  heldMessages: { send: (bytes: Buffer) => void; bytes: Buffer }[];
  waiters: { count: number; wake: () => void }[];
}
const HEAD_END = Buffer.from("\r\n\r\n");
const MAX_HEAD = 64 * 1024;

/** Splits complete frames off `buffer`; returns them with the unconsumed rest. */
function frames(buffer: Buffer): { frames: { bytes: Buffer; fin: boolean; opcode: number }[]; rest: Buffer } {
  const out: { bytes: Buffer; fin: boolean; opcode: number }[] = [];
  let offset = 0;
  while (buffer.length - offset >= 2) {
    const first = buffer[offset]!, second = buffer[offset + 1]!;
    let length = second & 0x7f, header = 2;
    if (length === 126) {
      if (buffer.length - offset < 4) break;
      length = buffer.readUInt16BE(offset + 2); header = 4;
    } else if (length === 127) {
      if (buffer.length - offset < 10) break;
      const big = buffer.readBigUInt64BE(offset + 2);
      if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("WebSocket frame too large to relay");
      length = Number(big); header = 10;
    }
    if (second & 0x80) header += 4;
    if (buffer.length - offset < header + length) break;
    out.push({ bytes: buffer.subarray(offset, offset + header + length), fin: (first & 0x80) !== 0, opcode: first & 0x0f });
    offset += header + length;
  }
  return { frames: out, rest: buffer.subarray(offset) };
}

export class SyncLinkProxy {
  readonly url: string;
  private readonly directions: Record<SyncLinkDirection, DirectionState>;
  private readonly sockets = new Set<Socket>();
  private readonly upgraded = new Set<{ device: Socket; home: Socket }>();
  private severed = false;
  private closed = false;
  private disown: () => void = () => {};
  private constructor(private readonly server: Server, port: number, private readonly target: { host: string; port: number }) {
    this.url = `http://127.0.0.1:${port}`;
    const state = (): DirectionState => ({ seen: 0, forwarded: 0, dropped: 0, duplicated: 0, dropNext: 0,
      duplicateNext: 0, holding: false, heldMessages: [], waiters: [] });
    this.directions = { to_home: state(), to_device: state() };
  }
  /** `target` is the home's own origin, e.g. primary.url. */
  static async start(options: { readonly target: string }): Promise<SyncLinkProxy> {
    assertFlowActive();
    if (process.platform !== "linux") throw new Error("SyncLinkProxy is Linux-only");
    const target = new URL(options.target);
    if (target.protocol !== "http:" || (target.hostname !== "127.0.0.1" && target.hostname !== "localhost"))
      throw new TypeError("SyncLinkProxy relays a loopback http origin only");
    let proxy: SyncLinkProxy | undefined;
    const server = createServer(device => proxy!.accept(device));
    await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve) });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("SyncLinkProxy has no loopback port");
    proxy = new SyncLinkProxy(server, address.port, { host: target.hostname, port: Number(target.port) });
    proxy.disown = ownResource(() => proxy!.close());
    return proxy;
  }
  counts(direction: SyncLinkDirection): SyncLinkCounts {
    const d = this.directions[direction];
    return { seen: d.seen, forwarded: d.forwarded, dropped: d.dropped, duplicated: d.duplicated, held: d.heldMessages.length };
  }
  drop(direction: SyncLinkDirection, count: number): void { this.positive(count); this.directions[direction].dropNext += count }
  duplicate(direction: SyncLinkDirection, count: number): void { this.positive(count); this.directions[direction].duplicateNext += count }
  hold(direction: SyncLinkDirection): void { this.directions[direction].holding = true }
  /** Sends every held message, in arrival order or reversed, and stops holding. */
  release(direction: SyncLinkDirection, options: { readonly order: "fifo" | "reverse" }): void {
    const d = this.directions[direction];
    d.holding = false;
    const held = d.heldMessages.splice(0);
    if (options.order === "reverse") held.reverse();
    for (const message of held) { message.send(message.bytes); d.forwarded++ }
  }
  /** Closes every relayed WebSocket and refuses new upgrades until heal(). Plain HTTP still passes. */
  cut(): void {
    this.severed = true;
    for (const pair of this.upgraded) { pair.device.destroy(); pair.home.destroy() }
    this.upgraded.clear();
  }
  heal(): void { this.severed = false }
  /** Resolves once `count` whole messages have arrived in `direction` since start. */
  async awaitSeen(direction: SyncLinkDirection, count: number, timeoutMs: number = LIMITS.requestMs): Promise<void> {
    const d = this.directions[direction];
    if (d.seen >= count) return;
    let wake: () => void = () => {};
    const waiter = { count, wake: () => wake() };
    d.waiters.push(waiter);
    try { await withDeadline(new Promise<void>(resolve => { wake = resolve; if (d.seen >= count) resolve() }), timeoutMs, `sync link ${direction} seen ${count}`) }
    finally { d.waiters.splice(d.waiters.indexOf(waiter), 1) }
  }
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true; this.disown();
    for (const socket of this.sockets) socket.destroy();
    await new Promise<void>(resolve => this.server.close(() => resolve()));
  }
  private positive(count: number): void { if (!Number.isInteger(count) || count < 1) throw new TypeError("count must be a positive integer") }
  private accept(device: Socket): void {
    this.sockets.add(device);
    device.once("close", () => this.sockets.delete(device));
    device.on("error", () => device.destroy());
    let head = Buffer.alloc(0);
    const onHead = (chunk: Buffer): void => {
      head = Buffer.concat([head, chunk]);
      const end = head.indexOf(HEAD_END);
      if (end < 0) { if (head.length > MAX_HEAD) device.destroy(); return }
      device.off("data", onHead);
      const request = head.subarray(0, end + 4), after = head.subarray(end + 4);
      const upgrade = /^GET \S+ HTTP\/1\.1\r\n/.test(request.toString("latin1")) && /\r\nupgrade:\s*websocket\s*\r\n/i.test(request.toString("latin1"));
      if (upgrade && this.severed) {
        device.end("HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        return;
      }
      const home = connect(this.target.port, this.target.host);
      this.sockets.add(home);
      home.once("close", () => { this.sockets.delete(home); device.destroy() });
      device.once("close", () => home.destroy());
      home.on("error", () => home.destroy());
      if (!upgrade) {
        home.write(Buffer.concat([request, after]));
        device.pipe(home); home.pipe(device);
        return;
      }
      const pair = { device, home };
      home.write(request);
      this.relayFrames(device, home, "to_home", after, pair);
      let answer = Buffer.alloc(0);
      const onAnswer = (chunk: Buffer): void => {
        answer = Buffer.concat([answer, chunk]);
        const stop = answer.indexOf(HEAD_END);
        if (stop < 0) { if (answer.length > MAX_HEAD) home.destroy(); return }
        home.off("data", onAnswer);
        const status = answer.subarray(0, stop + 4);
        device.write(status);
        if (!/^HTTP\/1\.1 101 /.test(status.toString("latin1"))) { device.write(answer.subarray(stop + 4)); home.pipe(device); return }
        this.upgraded.add(pair);
        home.once("close", () => this.upgraded.delete(pair));
        this.relayFrames(home, device, "to_device", answer.subarray(stop + 4), pair);
      };
      home.on("data", onAnswer);
    };
    device.on("data", onHead);
  }
  /** Reads frames from `from`, acts on whole data messages, writes them to `to`. */
  private relayFrames(from: Socket, to: Socket, direction: SyncLinkDirection, first: Buffer, pair: { device: Socket; home: Socket }): void {
    const d = this.directions[direction];
    const send = (bytes: Buffer): void => { if (!to.destroyed) to.write(bytes) };
    let pending: Buffer = Buffer.alloc(0);
    let message: Buffer[] = [];
    const consume = (chunk: Buffer): void => {
      pending = pending.length ? Buffer.concat([pending, chunk]) : chunk;
      let parsed;
      try { parsed = frames(pending) } catch { pair.device.destroy(); pair.home.destroy(); return }
      pending = Buffer.from(parsed.rest);
      for (const frame of parsed.frames) {
        if (frame.opcode >= 0x8) { send(frame.bytes); continue }
        message.push(Buffer.from(frame.bytes));
        if (!frame.fin) continue;
        const whole = Buffer.concat(message); message = [];
        d.seen++;
        for (const waiter of [...d.waiters]) if (d.seen >= waiter.count) waiter.wake();
        if (d.dropNext > 0) { d.dropNext--; d.dropped++; continue }
        if (d.holding) { d.heldMessages.push({ send, bytes: whole }); continue }
        send(whole); d.forwarded++;
        if (d.duplicateNext > 0) { d.duplicateNext--; send(whole); d.forwarded++; d.duplicated++ }
      }
    };
    if (first.length) consume(first);
    from.on("data", consume);
  }
}
