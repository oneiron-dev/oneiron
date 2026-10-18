/** Public wire clients. Credentials grant nothing until the real server admits them. */
import { isAbsolute, resolve } from "node:path";
import { createPrivateKey, sign } from "node:crypto";
import { blake3 } from "@noble/hashes/blake3";
import { encode, decode } from "@msgpack/msgpack";
import type { FacadeInput, FacadeResult, FacadeVerb } from "@oneiron/client";
import type { ClaimInput, WitnessTurn, RecallOptions } from "oneiron";
import { LIMITS, redactor, runProcess, withDeadline, secretHex, ownResource } from "./run.ts";
import type { Artifacts, ProcessResult } from "./run.ts";
import { requireAsset } from "./fixtures.ts";
import type { BuildManifest } from "./fixtures.ts";

export interface WireError { readonly code: string; readonly message: string; readonly suggestions?: readonly string[]; readonly [key:string]: unknown }
export interface WireReply<T = unknown> {
  readonly status: number; readonly headers: Headers; readonly body: T; readonly raw: string; readonly bytes:Uint8Array;
}
/** Keeps the original status, headers and full error envelope, including unknown typed fields. */
export class PublicHttpError extends Error {
  override name = "PublicHttpError";
  constructor(readonly reply: WireReply<unknown>) { super(`HTTP ${reply.status}`) }
  get error(): WireError | undefined {
    const payload=(this.reply.body as {error?:unknown} | null)?.error ?? this.reply.body;
    if (!payload || typeof payload!=="object") return undefined;
    const fields=payload as Record<string,unknown>;
    return typeof fields.code==="string"&&typeof fields.message==="string" ? payload as WireError : undefined;
  }
}
export function credentialParts(credential: string): { bearer: string; seed: string } {
  const match = /^v2\.cred\.([a-f0-9]+)\.([a-f0-9]{64})$/.exec(credential);
  if (!match) throw new TypeError("Expected paired v2 credential (value withheld)");
  const bearer = `v2.slip.${match[1]!}`;
  const seed = match[2]!;
  redactor.add(credential,bearer,seed,match[1]!);
  return {bearer,seed};
}
/** Exact public holder transcript: hash canonical token bytes, not locally reconstructed claims. */
export function boundHeaders(credential: string): Headers {
  const {bearer,seed} = credentialParts(credential);
  const timestamp = Math.floor(Date.now()/1000);
  const nonce = secretHex(16);
  const challenge = Buffer.from(`oneiron-request:${timestamp}:${nonce}`);
  const length = Buffer.alloc(8); length.writeBigUInt64BE(BigInt(challenge.length));
  const transcript = Buffer.concat([Buffer.from("oneiron/slip-binding/v2\0"),Buffer.from(blake3(Buffer.from(bearer.slice(8),"hex"))),length,challenge]);
  const key = createPrivateKey({key:Buffer.concat([Buffer.from("302e020100300506032b657004220420","hex"),Buffer.from(seed,"hex")]),format:"der",type:"pkcs8"});
  const proof = JSON.stringify({timestamp,nonce,signature:sign(null,transcript,key).toString("hex")});
  redactor.add(proof);
  return new Headers({authorization:`Bearer ${bearer}`,"x-oneiron-binding":proof});
}
export interface HttpOptions {
  readonly credential?: string;
  readonly timeoutMs?: number;
  readonly artifacts?: Artifacts;
}
export class PublicHttpClient {
  readonly url: URL;
  constructor(url: string, readonly options: HttpOptions = {}) {
    this.url = new URL(url);
    if (!/^https?:$/.test(this.url.protocol) || this.url.username || this.url.password) throw new TypeError("Invalid HTTP origin");
    if (options.credential) credentialParts(options.credential);
  }
  /** Raw public request for existing non-facade endpoints and malformed-wire cases; no invented verbs. */
  async raw<T = unknown>(method: string, path: string, body?: unknown, headers?: HeadersInit): Promise<WireReply<T>> {
    const url = new URL(path,this.url);
    if (url.origin !== this.url.origin) throw new TypeError("Cross-origin credential request refused");
    const bound = this.options.credential ? boundHeaders(this.options.credential) : new Headers();
    for (const [name,value] of new Headers(headers)) bound.set(name,value);
    if (body !== undefined && !bound.has("content-type")) bound.set("content-type","application/json");
    const response = await fetch(url,{method,headers:bound,redirect:"manual",signal:AbortSignal.timeout(this.options.timeoutMs ?? LIMITS.requestMs),
      ...(body === undefined ? {} : {body: typeof body === "string" || body instanceof Uint8Array ? body : JSON.stringify(body)})});
    const bytes = new Uint8Array(await response.arrayBuffer());
    const raw = new TextDecoder().decode(bytes);
    let parsed: unknown = raw;
    try { parsed = JSON.parse(raw) } catch { /* Raw text is part of the response, not a fabricated envelope. */ }
    const reply = {status:response.status,headers:response.headers,body:parsed as T,raw,bytes};
    // Bodies can contain fixture secrets; log only on explicit Artifacts calls by the test.
    await this.options.artifacts?.json(`http-${secretHex(6)}.json`,{method,path:url.pathname,status:response.status,headers:Object.fromEntries(response.headers)});
    return reply;
  }
  async request<T = unknown>(method: string, path: string, body?: unknown, headers?: HeadersInit): Promise<WireReply<T>> {
    const reply = await this.raw<T>(method,path,body,headers);
    if (reply.status < 200 || reply.status >= 300) throw new PublicHttpError(reply);
    return reply;
  }
  /** Only catalogued, typed calls. 202 PENDING_ASK is retained as an error, never cast to success. */
  async call<V extends FacadeVerb>(verb: V, input: FacadeInput<V>): Promise<FacadeResult<V>> {
    const reply = await this.request<FacadeResult<V>>("POST",`/v1/core/facade/${verb}`,input,{"x-oneiron-invocation":secretHex(16)});
    if (reply.status === 202 && typeof reply.body === "object" && reply.body && "error" in reply.body) throw new PublicHttpError(reply);
    return reply.body;
  }
}
export interface JsonRpcError { readonly code: number; readonly message: string; readonly data?: unknown }
export type JsonRpcReply<T> = { readonly jsonrpc:"2.0";readonly id:number;readonly result:T } |
  { readonly jsonrpc:"2.0";readonly id:number;readonly error:JsonRpcError };
export class McpRpcError extends Error {
  override name = "McpRpcError";
  constructor(readonly response: JsonRpcReply<unknown>) { super("MCP JSON-RPC refusal") }
}
export class McpClient {
  private nextId = 1;
  constructor(readonly http: PublicHttpClient, readonly surface: "primary" | "tool-first" = "tool-first") {}
  async rpc<T = unknown>(method: string, params: unknown = {}): Promise<JsonRpcReply<T>> {
    const id = this.nextId++;
    const reply = await this.http.request<JsonRpcReply<T>>("POST",this.surface === "primary" ? "/mcp" : "/mcp/tool-first",
      {jsonrpc:"2.0",id,method,params},{accept:"application/json"});
    if (reply.body.jsonrpc !== "2.0" || reply.body.id !== id) throw new Error("MCP reply id/version mismatch");
    return reply.body;
  }
  async request<T = unknown>(method: string, params: unknown = {}): Promise<T> {
    const response = await this.rpc<T>(method,params);
    if ("error" in response) throw new McpRpcError(response);
    return response.result;
  }
  initialize(): Promise<unknown> {
    return this.request("initialize",{protocolVersion:"2024-11-05",capabilities:{},clientInfo:{name:"oneiron-e2e",version:"0.1.0"}});
  }
  listTools(): Promise<unknown> { return this.request("tools/list") }
  callTool(name: string, args: unknown): Promise<unknown> {
    return this.request("tools/call",{name,arguments:args,_meta:{"oneiron/invocation":secretHex(16)}});
  }
  close(): void { /* HTTP MCP on this head has no held session to close. */ }
}

export interface WsEnvelope<T = unknown> {
  readonly type: string; readonly id: number; readonly seq: number; readonly last: boolean; readonly payload: T;
  readonly receipt_ref?: string | null; readonly no_record?: boolean;
}
export interface WsFrame { readonly tag: number; readonly envelope: WsEnvelope }
/** App-tier v8 on the real /ws socket. No compression is advertised; no CRDT is interpreted. */
export class WsClient {
  private readonly queue: WsFrame[] = [];
  private readonly waiters: {resolve:(frame:WsFrame)=>void;reject:(error:unknown)=>void}[] = [];
  private failure: Error | undefined;
  private nextId = 1;
  private readonly disown: () => void;
  private constructor(readonly socket: WebSocket) {
    this.disown = ownResource(() => this.close());
    socket.binaryType = "arraybuffer";
    socket.addEventListener("message",event => {
      try {
        if (!(event.data instanceof ArrayBuffer)) throw new Error("Expected binary WS frame");
        const bytes = new Uint8Array(event.data);
        if (bytes[0] === 3) return;
        if (bytes[0] !== 30 && bytes[0] !== 31) return; // Sync frames remain available through a separate caller-owned raw socket.
        const frame = {tag:bytes[0],envelope:decode(bytes.subarray(1)) as WsEnvelope};
        const waiter = this.waiters.shift();
        if (waiter) waiter.resolve(frame); else this.queue.push(frame);
      } catch (error) { this.fail(error instanceof Error ? error : new Error(String(error))) }
    });
    socket.addEventListener("error",() => this.fail(new Error("WS transport error")));
    socket.addEventListener("close",event => this.fail(new Error(`WS closed ${event.code}: ${event.reason}`)));
  }
  private fail(error: Error): void { this.failure = error; for (const waiter of this.waiters.splice(0)) waiter.reject(error) }
  static async connect(origin: string, credential: string, timeoutMs: number = LIMITS.requestMs): Promise<WsClient> {
    const url = new URL("/ws",origin); url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    // lib.dom hides Bun's client constructor overload for authentication headers.
    const BunWebSocket = WebSocket as typeof WebSocket & {
      new (url: string | URL, options?: Bun.WebSocketOptions): WebSocket;
    };
    const socket = new BunWebSocket(url.href,{headers:Object.fromEntries(boundHeaders(credential))});
    const client = new WsClient(socket);
    try {
      await withDeadline(new Promise<void>((resolve,reject) => {
        socket.addEventListener("open",() => resolve(),{once:true});
        socket.addEventListener("error",() => reject(new Error("WS upgrade failed")),{once:true});
        socket.addEventListener("close",event => reject(new Error(`WS upgrade closed ${event.code}`)),{once:true});
      }),timeoutMs,"WS upgrade",() => socket.close());
      socket.send(new Uint8Array([3,8]));
      return client;
    } catch (error) { client.close(); throw error }
  }
  send(tag: 30 | 31, envelope: WsEnvelope): void {
    const packed = encode(envelope);
    const bytes = new Uint8Array(packed.length+1); bytes[0] = tag; bytes.set(packed,1); this.socket.send(bytes);
  }
  async next(timeoutMs: number = LIMITS.requestMs): Promise<WsFrame> {
    const queued = this.queue.shift(); if (queued) return queued;
    if (this.failure) throw this.failure;
    let pending: {resolve:(frame:WsFrame)=>void;reject:(error:unknown)=>void} | undefined;
    try { return await withDeadline(new Promise<WsFrame>((resolve,reject) => { pending={resolve,reject}; this.waiters.push(pending) }),timeoutMs,"WS frame") }
    finally { if (pending) { const i=this.waiters.indexOf(pending); if(i>=0) this.waiters.splice(i,1) } }
  }
  /** Sequential RPC helper. For multiplexed RPC/subscription assertions, use send/next explicitly. */
  async call<V extends FacadeVerb>(method: V, params: FacadeInput<V>): Promise<{value:FacadeResult<V>;frames:readonly WsFrame[]}> {
    const id = this.nextId++;
    this.send(30,{type:"rpc.req",id,seq:0,last:true,payload:{method,params}});
    const frames: WsFrame[] = []; const chunks: Uint8Array[] = [];
    const end = performance.now()+LIMITS.requestMs;
    for (;;) {
      const frame = await this.next(Math.max(1,end-performance.now())); frames.push(frame);
      const e = frame.envelope;
      if (e.id !== id || frame.tag !== 30) throw new Error("Use send/next for multiplexed sockets");
      if (e.type === "rpc.err") throw new WsRpcError(frames);
      if (e.type !== "rpc.res" || e.seq !== chunks.length || !(e.payload instanceof Uint8Array)) throw new Error("Invalid WS result chunks");
      chunks.push(e.payload);
      if (e.last) break;
    }
    const bytes = new Uint8Array(chunks.reduce((n,c) => n+c.length,0)); let offset=0;
    for (const chunk of chunks) { bytes.set(chunk,offset);offset+=chunk.length }
    return {value:decode(bytes) as FacadeResult<V>,frames};
  }
  close(): void { this.disown(); this.socket.close(); this.fail(new Error("WS client closed")) }
}
export class WsRpcError extends Error {
  override name = "WsRpcError";
  constructor(readonly frames: readonly WsFrame[]) { super("WS RPC refusal") }
}

export class CliClient {
  constructor(readonly binary: string, readonly cwd: string, readonly env: Readonly<Record<string,string>>,readonly artifacts?: Artifacts) {}
  async run(args: readonly string[], input?: string, timeoutMs: number = LIMITS.requestMs, privateOutput = false): Promise<ProcessResult> {
    return runProcess([this.binary,...args],{cwd:this.cwd,env:this.env,label:`cli-${secretHex(6)}`,privateOutput,
      ...(this.artifacts ? {artifacts:this.artifacts} : {}),...(input === undefined ? {} : {input})},timeoutMs);
  }
  async json<T = unknown>(args: readonly string[], input?: unknown): Promise<T> {
    const result = await this.run(args,input === undefined ? undefined : JSON.stringify(input));
    if (result.exitCode !== 0) throw new CliError(result);
    return JSON.parse(result.stdout) as T;
  }
  /** Typed facade only. A designed verb without this typed call remains test.todo. */
  call<V extends FacadeVerb>(verb: V, input: FacadeInput<V>): Promise<FacadeResult<V>> {
    return this.json(["api","call",verb,"--data","-"],input);
  }
}
export class CliError extends Error {
  override name = "CliError";
  constructor(readonly result: ProcessResult) { super(`CLI exited ${result.exitCode}`) }
}
export type SdkOperation =
  | { readonly verb:"witness";readonly input:WitnessTurn }
  | { readonly verb:"claimUpsert";readonly input:ClaimInput }
  | { readonly verb:"recall";readonly query:string;readonly options?:RecallOptions }
  | { readonly verb:"receipts";readonly limit?:number };
export interface PythonWitnessTurn {
  readonly conversation_ref:string;readonly turn_ref?:string;readonly occurred_at?:number;
  readonly messages:readonly {readonly id?:string;readonly author:"user"|"companion"|"system";readonly message_type:string;readonly content:string;readonly order:number}[];
}
export type PythonSdkOperation =
  | {readonly verb:"witness";readonly input:PythonWitnessTurn}
  | {readonly verb:"claimUpsert";readonly input:{readonly predicate:string;readonly subject_ref:string;readonly value:unknown;readonly confidence:number;readonly source:string;readonly world_ref?:string;readonly scope?:unknown}}
  | {readonly verb:"recall";readonly query:string;readonly options?:{readonly effort?:string;readonly scope?:unknown;readonly limit?:number;readonly as_of?:number}}
  | {readonly verb:"receipts";readonly limit?:number};
export type SdkTarget = {readonly mode:"remote";readonly url:string;readonly credential:string} |
  {readonly mode:"embedded";readonly path:string;readonly dimensions?:number};
export interface SdkDriverResult { readonly process:ProcessResult;readonly results:readonly ({ok:true;value:unknown}|{ok:false;error:unknown})[] }
const JS_DRIVER = String.raw`
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
const p=JSON.parse(readFileSync(0,'utf8'));
const {Oneiron}=await import(pathToFileURL(p.module).href);
function error(e){return {name:e.name,code:e.code,message:e.message,suggestions:e.suggestions,wrongRoot:e.wrongRoot,hook:e.hook}}
try {
 if(p.pair){const paired=Oneiron.pair(p.pair);process.stdout.write(JSON.stringify({credential:paired.credential,pin:paired.pin}));}
 else {
  const t=p.target;const m=t.mode==='remote'?Oneiron.connect(t.url,t.credential):Oneiron.open(t.path,{dimensions:t.dimensions});
  const results=p.operations.map(o=>{try {
   let value;
   switch(o.verb){case 'witness':value=m.vault.witness(o.input);break;case 'claimUpsert':value=m.vault.claims.upsert(o.input);break;
    case 'recall':value=m.vault.recall(o.query,o.options);break;case 'receipts':value=m.vault.receipts(o.limit);break;default:throw new Error('Unknown SDK operation')}
   return {ok:true,value};
  }catch(e){return {ok:false,error:error(e)}}});
  process.stdout.write(JSON.stringify(results));
 }
}catch(e){process.stdout.write(JSON.stringify({error:error(e)}));process.exitCode=1;}
`;
const PY_DRIVER = String.raw`
import json,sys
from oneiron import Oneiron
p=json.load(sys.stdin)
def err(e):
 return {k:getattr(e,k,None) for k in ('code','message','suggestions','wrong_root','hook')}
try:
 t=p['target']
 m=Oneiron.connect(t['url'],t['credential']) if t['mode']=='remote' else Oneiron.open(t['path'],dimensions=t.get('dimensions'))
 results=[]
 for o in p['operations']:
  try:
   v=o['verb']
   if v=='witness': value=m.vault.witness(o['input'])
   elif v=='claimUpsert': value=m.vault.claims.upsert(o['input'])
   elif v=='recall': value=m.vault.recall(o['query'],**o.get('options',{}))
   elif v=='receipts': value=m.vault.receipts(o.get('limit',100))
   else: raise ValueError('Unknown SDK operation')
   results.append({'ok':True,'value':value})
  except Exception as e: results.append({'ok':False,'error':err(e)})
 json.dump(results,sys.stdout)
except Exception as e:
 json.dump({'error':err(e)},sys.stdout);sys.exit(1)
`;
export class SdkProcessDriver {
  constructor(readonly build:BuildManifest,readonly cwd:string,readonly env:Readonly<Record<string,string>>) {}
  async pair(link:string): Promise<{credential:string;pin:unknown}> {
    redactor.add(link);
    const result=await runProcess([requireAsset(this.build,"node"),"--input-type=module","-e",JS_DRIVER],
      {cwd:this.cwd,env:this.env,input:JSON.stringify({module:requireAsset(this.build,"sdk-js"),pair:link}),privateOutput:true,label:"sdk-pair"});
    if(result.exitCode!==0) throw new CliError(result);
    const paired=JSON.parse(result.stdout) as {credential:string;pin:unknown};credentialParts(paired.credential);return paired;
  }
  /** Python inputs use the Python SDK's native snake_case fields; no harness casing conversion. */
  async run(language:"typescript"|"napi",target:SdkTarget,operations:readonly SdkOperation[]):Promise<SdkDriverResult>;
  async run(language:"python",target:SdkTarget,operations:readonly PythonSdkOperation[]):Promise<SdkDriverResult>;
  async run(language:"typescript"|"python"|"napi",target:SdkTarget,operations:readonly SdkOperation[] | readonly PythonSdkOperation[]):Promise<SdkDriverResult> {
    if(target.mode==="embedded"&&(!isAbsolute(target.path)||resolve(target.path)===resolve(this.cwd,"vault")))
      throw new TypeError("Embedded SDK requires its own absolute vault path, never the served vault");
    if(target.mode==="remote") credentialParts(target.credential);
    const argv=language==="python" ? [requireAsset(this.build,"python"),"-c",PY_DRIVER] : [requireAsset(this.build,"node"),"--input-type=module","-e",JS_DRIVER];
    const result=await runProcess(argv,{cwd:this.cwd,env:this.env,input:JSON.stringify({module:requireAsset(this.build,"sdk-js"),target,operations}),privateOutput:true,label:`sdk-${language}`});
    if(result.exitCode!==0) throw new CliError(result);
    return {process:result,results:JSON.parse(result.stdout) as SdkDriverResult["results"]};
  }
}
