/** Fresh real server processes; setup is public CLI/HTTP only. No engine crate bindings. */
import { createServer } from "node:net";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { createHash } from "node:crypto";
import { Artifacts, BlockedDoor, LIMITS, ManagedProcess, isolatedEnv, ownResource, redactor, secretHex, tempRoot, withDeadline } from "./run.ts";
import { loadBuildManifest, requireAsset } from "./fixtures.ts";
import type { BuildManifest, Profile } from "./fixtures.ts";
import { CliClient, CliError, PublicHttpClient, McpClient, SdkProcessDriver, WsClient, credentialParts } from "./clients.ts";
import type { FacadeInput, FacadeResult } from "@oneiron/client";

export interface PairedActor {
  readonly principalRef:string;readonly actorClass:"human"|"agent"|"system";
  readonly credential:string;readonly pin:unknown;
  readonly client:PublicHttpClient;readonly mcp:McpClient;readonly cli:CliClient;
}
export interface PairActorOptions {
  /** Must already exist through a public owner/person/agent door. Pairing never creates it. */
  readonly principalRef:string;readonly actorClass:"human"|"agent"|"system";
  readonly scope?:readonly string[];readonly lifetimeSeconds?:number;
}
export interface EndpointEmbedder {
  readonly endpoint:string;readonly modelKey:string;readonly modelId:string;readonly dimensions:number;
  readonly egress:{readonly allowAll:true}|{readonly entityIds:readonly string[]};
}
export interface EndpointTagger {readonly url:string;readonly checkpointSha16:string;readonly labelCount:number;readonly mode?:"save"|"shadow"}
export interface EngineOptions {
  readonly profile:Profile;
  /** Applies only public policy calls, after real owner pairing. No implicit grants. */
  readonly policy?:(engine:EngineFixture)=>Promise<void>;
  /** Extra, independent vaults. No membership or sync authority is silently installed. */
  readonly peers?:number;
  readonly id?:string;
  /** Host configuration only. Read current public config before supplying TOML. */
  readonly serverConfig?:string;
  readonly initArgs?:readonly string[];
  readonly embedder?:EndpointEmbedder;
  readonly oneironer?:EndpointTagger;
  readonly surface?:"primary"|"tool-first";
  readonly capabilities?:readonly string[];
  /** Optional readiness predicate made solely of public reads; never retries a write. */
  readonly ready?:(client:PublicHttpClient)=>Promise<boolean>;
}
interface Schema {readonly paths?:Readonly<Record<string,unknown>>}
async function reservePort():Promise<{port:number;release:()=>Promise<void>}> {
  const server=createServer();
  await new Promise<void>((resolve,reject)=>{server.once("error",reject);server.listen(0,"127.0.0.1",resolve)});
  const address=server.address();
  if(!address||typeof address==="string") throw new Error("No assigned loopback port");
  return {port:address.port,release:()=>new Promise<void>((resolve,reject)=>server.close(error=>error?reject(error):resolve()))};
}
/** Observes public state; only readiness transport failures are repeatable, never mutations. */
export async function awaitPublic<T>(read:()=>Promise<T>,ready:(value:T)=>boolean,options:{readonly timeoutMs?:number;readonly label:string;readonly readiness?:boolean}):Promise<T> {
  const end=performance.now()+(options.timeoutMs??LIMITS.requestMs);
  let last:unknown;
  while(performance.now()<end) {
    try {const value=await withDeadline(read(),Math.max(1,end-performance.now()),options.label);last=value;if(ready(value)) return value}
    catch(error) {last=error;if(!options.readiness) throw error}
    const left=end-performance.now();
    if(left>0) await new Promise<void>(resolve=>setTimeout(resolve,Math.min(25,left)));
  }
  throw new Error(`${options.label} deadline; last public observation: ${redactor.text((JSON.stringify(last instanceof Error?{name:last.name,message:last.message}:last)??"undefined"))}`);
}
export class EngineFixture {
  readonly artifacts:Artifacts;
  cli:CliClient;
  readonly sdk:SdkProcessDriver;
  readonly peers:EngineFixture[]=[];
  readonly url:string;
  pairedActor!:PairedActor;
  client!:PublicHttpClient;
  mcp!:McpClient;
  private server:ManagedProcess|undefined;
  private closed=false;
  private disown:()=>void=()=>{};
  private constructor(readonly root:string,readonly build:BuildManifest,readonly env:Readonly<Record<string,string>>,readonly options:EngineOptions,port:number) {
    this.url=`http://127.0.0.1:${port}`;
    this.artifacts=new Artifacts(resolve(process.env.E2E_ARTIFACTS_DIR??resolve(root,"artifacts"),`${options.id??"engine"}-${secretHex(4)}`));
    this.cli=new CliClient(requireAsset(build,"cli"),root,env,this.artifacts);
    this.sdk=new SdkProcessDriver(build,root,env);
  }
  static async start(options:EngineOptions):Promise<EngineFixture> {
    const profile=process.env.E2E_PROFILE;
    if(profile&&profile!==options.profile) throw new BlockedDoor("Engine profile differs from scheduled profile");
    const build=await loadBuildManifest(options.profile);
    for(const capability of options.capabilities??[]) if(!build.capabilities.includes(capability)) throw new BlockedDoor(`waits on ${capability}`);
    const peers=options.peers??0;
    if(!Number.isInteger(peers)||peers<0) throw new TypeError("peers must be a nonnegative integer");
    if(peers>0&&process.env.E2E_FILE_SLOTS!=="2") throw new BlockedDoor("Multi-peer flows require a two-slot file");
    const root=await tempRoot(options.id??"engine");
    const env=isolatedEnv(root,build.environment);
    for(const key of Object.keys(env)) if(key.startsWith("ONEIRON_")) delete env[key];
    env.ONEIRON_AUTH_SECRET=secretHex();redactor.add(env.ONEIRON_AUTH_SECRET);
    await mkdir(env.TMPDIR!,{recursive:true,mode:0o700});
    const reservation=await reservePort();
    const engine=new EngineFixture(root,build,env,options,reservation.port);
    let released=false;
    try {
      const config=resolve(root,"oneiron.toml");
      if(options.serverConfig&&/^\s*(host|port|vault_path|auth_secret|allow_unauthenticated)\s*=/m.test(options.serverConfig))
        throw new TypeError("EngineFixture owns isolation/auth fields; use an explicit unauthenticated case outside the default fixture");
      if(options.serverConfig?.trim()&&!options.serverConfig.trim().startsWith("[")) throw new TypeError("serverConfig is additional public TOML tables, not root keys");
      const embedder=options.embedder;
      const tagger=options.oneironer;
      const endpointArgs=embedder?["--embedder","endpoint","--embedder-endpoint",embedder.endpoint,"--embedder-model-key",embedder.modelKey,
        "--embedder-model-id",embedder.modelId,"--dimensions",String(embedder.dimensions),
        ...("allowAll" in embedder.egress?["--embedder-egress-allow-all"]:["--embedder-egress-allow",embedder.egress.entityIds.join(",")])]:["--embedder","none"];
      const taggerArgs=tagger?["--oneironer","endpoint","--oneironer-url",tagger.url,"--oneironer-checkpoint-sha16",tagger.checkpointSha16,
        "--oneironer-label-count",String(tagger.labelCount),"--oneironer-mode",tagger.mode??"save"]:["--oneironer","none"];
      await writeFile(config,`host = "127.0.0.1"\nport = ${reservation.port}\n\n[keystore]\nbackend = "off"\n${options.serverConfig??""}`,{mode:0o600});
      const init=await engine.cli.run(["init",resolve(root,"vault"),"--config",config,...endpointArgs,...taggerArgs,...(options.initArgs??[])],undefined,LIMITS.readyMs,true);
      if(init.exitCode!==0) throw new CliError(init);
      const bootstrap=await engine.cli.run(["token","bootstrap","--url",engine.url,"--config",config],undefined,LIMITS.readyMs,true);
      if(bootstrap.exitCode!==0) throw new CliError(bootstrap);
      const link=bootstrap.stdout.trim();redactor.add(link);
      const principalRef=new URL(link).hash.slice(1).split(".")[1];
      if(!principalRef||!/^[a-f0-9]{32}$/.test(principalRef)) throw new Error("Owner bootstrap returned no bound principal");
      await reservation.release();released=true;
      await engine.launch();
      const paired=await engine.sdk.pair(link);
      engine.pairedActor=engine.actor(principalRef,"human",paired);
      engine.client=engine.pairedActor.client;engine.mcp=engine.pairedActor.mcp;engine.cli=engine.pairedActor.cli;
      const schema=await engine.client.request<Schema>("GET","/api/openapi.json");
      await engine.artifacts.json("public-schema.json",schema.body);
      if(options.ready) await awaitPublic(()=>options.ready!(engine.client),Boolean,{timeoutMs:LIMITS.readyMs,label:"requested public capabilities"});
      const configBytes=await readFile(config);
      await engine.artifacts.json("launch.json",{profile:options.profile,buildHead:build.head,url:engine.url,
        buildManifestSha256:process.env.E2E_BUILD_MANIFEST_SHA256,configSha256:createHash("sha256").update(configBytes).digest("hex"),
        config:redactor.text(configBytes.toString()),capabilities:options.capabilities??[]});
      engine.disown=ownResource(()=>engine.close());
      if(options.policy) await options.policy(engine);
      for(let i=0;i<peers;i++) {
        const {peers:_count,...peerOptions}=options;
        engine.peers.push(await EngineFixture.start({...peerOptions,id:`${options.id??"engine"}-peer-${i}`,peers:0}));
      }
      return engine;
    } catch(error) {
      if(!released) await reservation.release();
      await engine.close().catch(()=>{});throw error;
    }
  }
  private actor(principalRef:string,actorClass:PairedActor["actorClass"],paired:{credential:string;pin:unknown}):PairedActor {
    const client=new PublicHttpClient(this.url,{credential:paired.credential,artifacts:this.artifacts});
    const {bearer,seed}=credentialParts(paired.credential);
    const cli=new CliClient(requireAsset(this.build,"cli"),this.root,{...this.env,ONEIRON_URL:this.url,ONEIRON_TOKEN:bearer,ONEIRON_SECRET:bearer,ONEIRON_BINDING_KEY:seed},this.artifacts);
    return {principalRef,actorClass,...paired,client,mcp:new McpClient(client,this.options.surface),cli};
  }
  private async launch():Promise<void> {
    const server=await ManagedProcess.start([requireAsset(this.build,"server"),"serve","--config",resolve(this.root,"oneiron.toml")],
      {cwd:this.root,env:this.env,label:`server-${secretHex(4)}`,artifacts:this.artifacts});
    this.server=server;
    const publicClient=new PublicHttpClient(this.url,{timeoutMs:1000});
    await awaitPublic(async()=>{
      if(!server.running) throw new Error(`Owned server exited: ${server.tail()}`);
      return publicClient.raw("GET","/api/health");
    },reply=>server.running&&reply.status===200,{timeoutMs:LIMITS.readyMs,label:"owned server HTTP health",readiness:true});
  }
  async pairActor(options:PairActorOptions):Promise<PairedActor> {
    const result=await this.pairedActor.cli.run(["token","pair","--url",this.url,"--principal-ref",options.principalRef,"--actor-class",options.actorClass,
      ...(options.scope?["--scope",options.scope.join(",")]:[]),...(options.lifetimeSeconds===undefined?[]:["--lifetime-secs",String(options.lifetimeSeconds)])],undefined,LIMITS.requestMs,true);
    if(result.exitCode!==0) throw new CliError(result);
    const link=result.stdout.trim();redactor.add(link);
    return this.actor(options.principalRef,options.actorClass,await this.sdk.pair(link));
  }
  /** Only public receipt reads, never a private job drain or an internal commit counter. */
  async awaitReceipt(ref:string,timeoutMs:number=LIMITS.requestMs):Promise<unknown> {
    if(ref.startsWith("call:")) return awaitPublic(()=>this.client.call("vault.receipts.get",{receipt_ref:ref}),value=>value!==null,
      {timeoutMs,label:`receipt ${ref}`});
    return awaitPublic(()=>this.client.call("vault.receipts",{limit:1000}),rows=>rows.some(row=>row.receipt_ref===ref),
      {timeoutMs,label:`receipt ${ref}`}).then(rows=>rows.find(row=>row.receipt_ref===ref));
  }
  async websocket(actor:PairedActor=this.pairedActor):Promise<WsClient> {return WsClient.connect(this.url,actor.credential)}
  /** Requires an existing typed door; never maps a missing canon verb to a generic endpoint. */
  async requireHttpDoor(path:string,method:string):Promise<void> {
    const schema=await this.client.request<{paths:Record<string,Record<string,unknown>>}>("GET","/api/openapi.json");
    if(!schema.body.paths[path]?.[method.toLowerCase()]) throw new BlockedDoor(`waits on ${method} ${path}`);
  }
  async restart():Promise<void> {
    if(this.closed) throw new Error("Cannot restart closed fixture");
    await this.server?.stop();await this.launch();
    await this.client.call("vault.receipts",{limit:1});
  }
  /** Caller first observes a public receipt, ACK or provider barrier; this method invents none. */
  async kill():Promise<void> {await this.server?.stop("SIGKILL")}
  async close(options:{readonly retainVault?:boolean}={}):Promise<void> {
    if(this.closed) return;this.closed=true;this.disown();
    const results=await Promise.allSettled(this.peers.map(peer=>peer.close(options)));
    await this.server?.stop();this.mcp?.close();
    if(!options.retainVault) await rm(this.root,{recursive:true,force:true});
    else if(process.env.E2E_TEMP_ROOT) await writeFile(resolve(process.env.E2E_TEMP_ROOT,"retain-vaults"),"explicit local retention\n",{mode:0o600});
    const failure=results.find(result=>result.status==="rejected");if(failure?.status==="rejected") throw failure.reason;
  }
}
export type PublicReceiptInput=FacadeInput<"vault.receipts">;
export type PublicReceipt=FacadeResult<"vault.receipts">[number];
