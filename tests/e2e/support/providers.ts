/** Scripted external origins only. Storage, gates, schedulers and organ executables remain real. */
import { gunzipSync } from "node:zlib";
import { ownResource, redactor, withDeadline, LIMITS } from "./run.ts";
import type { Artifacts } from "./run.ts";

export type Json = null | boolean | number | string | readonly Json[] | {readonly [key:string]:Json};
export interface ProviderUsage { readonly inputTokens:number; readonly outputTokens:number }
export type ProviderResponse =
  | {readonly kind:"json";readonly body:Json;readonly status?:number;readonly headers?:Readonly<Record<string,string>>}
  | {readonly kind:"bytes";readonly body:Uint8Array;readonly contentType:string;readonly status?:number}
  | {readonly kind:"stream";readonly contentType:string;readonly status?:number;readonly parts:readonly StreamPart[]};
export interface StreamPart {
  readonly id:string;
  /** Exact protocol bytes; SSE event names, deltas and usage are fixture-authored. */
  readonly data:string|Uint8Array;
  readonly barrier?:string;
}
export interface ProviderStep {
  readonly id:string;
  /** Logical origin returned in urls. Use a separate origin per role when the wire carries no role. */
  readonly origin:string;
  readonly role:string;
  readonly purpose:string;
  readonly request:{readonly method:"GET"|"POST"|"PUT"|"PATCH"|"DELETE";readonly path:string;readonly model?:string;
    /** Subset of public protocol fields, never a generated-prompt string match. */
    readonly fields?:Readonly<Record<string,Json>>};
  readonly response:ProviderResponse;
  readonly barrier?:string;
}
export interface ProviderSocket {
  readonly id:string;readonly origin:string;readonly path:string;readonly role:string;readonly purpose:string;
  /** Ordered real client messages and exact server frames. Audio bytes stay binary. */
  readonly exchanges:readonly {readonly request:Json|Uint8Array;readonly replies:readonly StreamPart[]}[];
}
interface SocketState {script:ProviderSocket;index:number;pending:Promise<void>}
export interface ProviderScenario { readonly id:string;readonly steps:readonly ProviderStep[];readonly sockets?:readonly ProviderSocket[];readonly artifacts?:Artifacts }
export interface SeenFixtureCall {
  readonly fixtureId:string|null;readonly origin:string;readonly sequence:number;readonly role:string|null;readonly purpose:string|null;
  readonly method:string;readonly path:string;readonly body:unknown;
}
export class ProviderScriptError extends Error { override name="ProviderScriptError" }
function subset(expected:Json,actual:unknown):boolean {
  if(Array.isArray(expected)) return Array.isArray(actual)&&expected.length===actual.length&&expected.every((v,i)=>subset(v,actual[i]));
  if(expected&&typeof expected==="object") return !!actual&&typeof actual==="object"&&Object.entries(expected).every(([k,v])=>subset(v,(actual as Record<string,unknown>)[k]));
  return Object.is(expected,actual);
}
function event(data:Json,name?:string):string {return `${name ? `event: ${name}\n` : ""}data: ${JSON.stringify(data)}\n\n`}
/** Usage is declared by the independent scenario, never estimated from engine prompts. */
export function openaiText(id:string,model:string,text:string,usage:ProviderUsage):ProviderResponse {
  return {kind:"json",body:{id,object:"chat.completion",model,choices:[{index:0,message:{role:"assistant",content:text},finish_reason:"stop"}],
    usage:{prompt_tokens:usage.inputTokens,completion_tokens:usage.outputTokens,total_tokens:usage.inputTokens+usage.outputTokens}}};
}
export function anthropicText(id:string,model:string,text:string,usage:ProviderUsage):ProviderResponse {
  return {kind:"json",body:{id,type:"message",role:"assistant",model,content:[{type:"text",text}],stop_reason:"end_turn",
    usage:{input_tokens:usage.inputTokens,output_tokens:usage.outputTokens}}};
}
export function openaiStream(id:string,model:string,deltas:readonly string[],usage:ProviderUsage):ProviderResponse {
  return {kind:"stream",contentType:"text/event-stream",parts:[
    ...deltas.map((text,i)=>({id:`${id}:delta:${i}`,data:event({id,object:"chat.completion.chunk",model,choices:[{index:0,delta:{content:text},finish_reason:null}]})})),
    {id:`${id}:stop`,data:event({id,model,choices:[{index:0,delta:{},finish_reason:"stop"}]})},
    {id:`${id}:usage`,data:event({id,model,choices:[],usage:{prompt_tokens:usage.inputTokens,completion_tokens:usage.outputTokens,total_tokens:usage.inputTokens+usage.outputTokens}})},
    {id:`${id}:done`,data:"data: [DONE]\n\n"}]};
}
export function anthropicStream(id:string,model:string,deltas:readonly string[],usage:ProviderUsage):ProviderResponse {
  const named=(type:string,fields:Readonly<Record<string,Json>>) => event({type,...fields},type);
  return {kind:"stream",contentType:"text/event-stream",parts:[
    {id:`${id}:start`,data:named("message_start",{message:{id,type:"message",role:"assistant",model,content:[],usage:{input_tokens:usage.inputTokens,output_tokens:0}}})},
    {id:`${id}:block`,data:named("content_block_start",{index:0,content_block:{type:"text",text:""}})},
    ...deltas.map((text,i)=>({id:`${id}:delta:${i}`,data:named("content_block_delta",{index:0,delta:{type:"text_delta",text}})})),
    {id:`${id}:block-stop`,data:named("content_block_stop",{index:0})},
    {id:`${id}:usage`,data:named("message_delta",{delta:{stop_reason:"end_turn"},usage:{output_tokens:usage.outputTokens}})},
    {id:`${id}:stop`,data:named("message_stop",{})}]};
}
export function embeddingReply(model:string,vectors:readonly (readonly number[])[],inputTokens:number):ProviderResponse {
  return {kind:"json",body:{object:"list",model,data:vectors.map((embedding,index)=>({object:"embedding",index,embedding})),usage:{prompt_tokens:inputTokens,total_tokens:inputTokens}}};
}
/** Exact connector/tagger/media protocol bodies use ProviderResponse, not a synthetic engine response. */
export class ScriptedProviders {
  readonly urls:Readonly<Record<string,string>>;
  private readonly servers:Bun.Server<SocketState>[]=[];
  private readonly sockets=new Map<string,ProviderSocket[]>();
  private readonly socketStates:SocketState[]=[];
  private readonly pending=new Map<string,ProviderStep[]>();
  private readonly seen:SeenFixtureCall[]=[];
  private readonly violations:string[]=[];
  private readonly barriers=new Map<string,{promise:Promise<void>;release:()=>void}>();
  private readonly released=new Set<string>();
  private readonly waiting=new Map<string,Set<()=>void>>();
  private readonly reached=new Set<string>();
  private closed=false;
  private disown:()=>void=()=>{};
  private constructor(readonly scenario:ProviderScenario) {this.urls={}}
  static async start(scenario:ProviderScenario):Promise<ScriptedProviders> {
    if(process.platform!=="linux") throw new ProviderScriptError("Provider execution is Linux-only");
    const instance=new ScriptedProviders(scenario);
    const ids=new Set<string>();
    for(const step of scenario.steps) {
      if(!step.id||!step.role||!step.purpose||ids.has(step.id)) throw new ProviderScriptError("Provider steps require unique IDs, role and purpose");
      ids.add(step.id);
      const queue=instance.pending.get(step.origin)??[];queue.push(step);instance.pending.set(step.origin,queue);
    }
    for(const script of scenario.sockets??[]) {
      if(ids.has(script.id)||!script.role||!script.purpose) throw new ProviderScriptError("Socket scripts require unique ID, role and purpose");
      ids.add(script.id);
      const queue=instance.sockets.get(script.origin)??[];queue.push(script);instance.sockets.set(script.origin,queue);
    }
    const urls:Record<string,string>={};
    try {
      for(const origin of [...new Set([...instance.pending.keys(),...instance.sockets.keys()])].sort()) {
        const server=Bun.serve<SocketState>({hostname:"127.0.0.1",port:0,idleTimeout:0,
          fetch:(request,server)=>{
            if(request.headers.get("upgrade")?.toLowerCase()!=="websocket") return instance.answer(origin,request);
            const script=instance.sockets.get(origin)?.shift();
            if(!script||script.path!==new URL(request.url).pathname) {
              instance.violations.push(`Unexpected WS provider upgrade on ${origin}`);return new Response("Unexpected fixture upgrade",{status:500});
            }
            const state:SocketState={script,index:0,pending:Promise.resolve()};instance.socketStates.push(state);
            if(server.upgrade(request,{data:state})) return;
            instance.violations.push(`WS provider upgrade refused on ${origin}`);return new Response("Upgrade refused",{status:500});
          },
          websocket:{message(socket,message){
            const state=socket.data;
            state.pending=state.pending.then(()=>instance.socketMessage(origin,state,message,data=>socket.send(data))).catch(error=>{
              instance.violations.push(String(error));socket.close(1011,"Fixture script mismatch");
            });
          }}});
        instance.servers.push(server);urls[origin]=`http://127.0.0.1:${server.port}`;
      }
      Object.assign(instance.urls,urls);
      instance.disown=ownResource(()=>instance.close());
      return instance;
    } catch(error) {for(const server of instance.servers) await server.stop(true);throw error}
  }
  private async socketMessage(origin:string,state:SocketState,message:string|Buffer,send:(data:string|Uint8Array)=>unknown):Promise<void> {
    const exchange=state.script.exchanges[state.index++];
    let body:unknown=message;
    if(typeof message==="string") {try {body=JSON.parse(message)} catch {body=message}}
    const expected=exchange?.request;
    const accepted=expected instanceof Uint8Array ? typeof message!=="string"&&Buffer.from(expected).equals(message) :
      exchange!==undefined&&subset(expected!,body);
    this.seen.push({fixtureId:accepted?state.script.id:null,origin,sequence:this.seen.length,role:state.script.role,
      purpose:state.script.purpose,method:"WS",path:state.script.path,body});
    if(!exchange||!accepted) throw new ProviderScriptError(`Unexpected WS provider message: ${state.script.id}`);
    for(const part of exchange.replies) {if(part.barrier) await this.hold(part.barrier);send(part.data)}
  }
  get seenFixtureCalls():readonly SeenFixtureCall[] {return structuredClone(this.seen)}
  releaseBarrier(name:string):void {
    this.released.add(name);this.barriers.get(name)?.release();
  }
  /** Wait for the provider to reach an explicit external boundary, not for an invented commit. */
  async awaitBarrier(name:string,timeoutMs:number=LIMITS.requestMs):Promise<void> {
    if(this.reached.has(name)) return;
    let wake:()=>void=()=>{};
    try {await withDeadline(new Promise<void>(resolve=>{wake=resolve;const set=this.waiting.get(name)??new Set();set.add(wake);this.waiting.set(name,set)}),timeoutMs,`provider barrier ${name}`)}
    finally {this.waiting.get(name)?.delete(wake)}
  }
  private async hold(name:string):Promise<void> {
    this.reached.add(name);for(const wake of this.waiting.get(name)??[]) wake();this.waiting.delete(name);
    if(this.released.has(name)) return;
    let barrier=this.barriers.get(name);
    if(!barrier) {let release=()=>{};const promise=new Promise<void>(resolve=>{release=resolve});barrier={promise,release};this.barriers.set(name,barrier)}
    await barrier.promise;
    if(this.closed) throw new ProviderScriptError("Provider closed at a barrier");
  }
  private async answer(origin:string,request:Request):Promise<Response> {
    let body:unknown=null;
    try {
      let bytes=new Uint8Array(await request.arrayBuffer());
      const codec=request.headers.get("content-encoding");
      if(codec==="gzip") bytes=new Uint8Array(gunzipSync(bytes));
      else if(codec&&codec!=="identity") throw new ProviderScriptError(`Unsupported declared request codec ${codec}`);
      if(bytes.length) {const raw=new TextDecoder().decode(bytes);try{body=JSON.parse(raw)}catch{body=bytes}}
      const step=this.pending.get(origin)?.shift();
      const path=new URL(request.url).pathname;
      const accepted=step&&step.request.method===request.method&&step.request.path===path&&
        (step.request.model===undefined||subset({model:step.request.model},body))&&
        (!step.request.fields||subset(step.request.fields,body));
      this.seen.push({fixtureId:accepted?step.id:null,origin,sequence:this.seen.length,role:step?.role??null,purpose:step?.purpose??null,method:request.method,path,body});
      if(!accepted) throw new ProviderScriptError(`Unexpected provider request on ${origin}: ${request.method} ${path}; expected ${step?.id??"no more calls"}`);
      if(step.barrier) await this.hold(step.barrier);
      const reply=step.response;
      if(reply.kind==="json") return Response.json(reply.body,{status:reply.status??200,...(reply.headers?{headers:reply.headers}:{})});
      if(reply.kind==="bytes") return new Response(reply.body,{status:reply.status??200,headers:{"content-type":reply.contentType}});
      const self=this;
      return new Response(new ReadableStream<Uint8Array>({async start(controller){
        try {for(const part of reply.parts){if(part.barrier) await self.hold(part.barrier);controller.enqueue(typeof part.data==="string"?new TextEncoder().encode(part.data):part.data)}controller.close()}
        catch(error){controller.error(error)}
      }}),{status:reply.status??200,headers:{"content-type":reply.contentType}});
    } catch(error) {
      this.violations.push(error instanceof Error?error.message:String(error));
      return Response.json({error:{type:"fixture_script_mismatch",message:"Unexpected fixture request"}},{status:500});
    }
  }
  async close():Promise<void> {
    if(this.closed) return;
    this.closed=true;this.disown();
    for(const barrier of this.barriers.values()) barrier.release();
    for(const server of this.servers) await server.stop(true);
    await Promise.all(this.socketStates.map(state=>state.pending));
    const unconsumed=[...this.pending.values()].flat().map(step=>step.id)
      .concat([...this.sockets.values()].flat().map(script=>script.id))
      .concat(this.socketStates.filter(state=>state.index<state.script.exchanges.length).map(state=>state.script.id));
    await this.scenario.artifacts?.json(`provider-${this.scenario.id}.json`,{scenario:this.scenario.id,script:this.scenario.steps,sockets:this.scenario.sockets??[],seen:redactor.value(this.seen),violations:this.violations,unconsumed});
    if(this.violations.length||unconsumed.length) throw new ProviderScriptError(`${this.scenario.id}: ${this.violations.join("; ")}; unconsumed: ${unconsumed.join(", ")}`);
  }
}
