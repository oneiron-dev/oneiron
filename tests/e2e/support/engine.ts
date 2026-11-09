/** Fresh real server processes; setup is public CLI/HTTP only. No engine crate bindings. */
import { createServer } from "node:net";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { createHash } from "node:crypto";
import { Artifacts, BlockedDoor, DeadlineError, LIMITS, ManagedProcess, isolatedEnv, ownResource, redactor, secretHex, tempRoot, withDeadline, recordStart, assertFlowActive } from "./run.ts";
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
  /** MRL prefix width; serialized at config root before [keystore] so init first-opens with it. Engine owns the 1 <= fd < dimensions check at open. */
  readonly fastDims?:number;
  readonly embedder?:EndpointEmbedder;
  /** `[embedder] idle_interval_ms`, written into the host config after init writes its
   * [embedder] table, as embeddings.test.ts does: public host policy, not a private tick. */
  readonly embedderIdleIntervalMs?:number;
  /** RUST_LOG for the served engine process only (never the CLI, whose stdout is parsed). Diagnostic; changes no behaviour. */
  readonly serverLog?:string;
  readonly oneironer?:EndpointTagger;
  readonly surface?:"primary"|"tool-first";
  readonly capabilities?:readonly string[];
  /** Optional readiness predicate made solely of public reads; never retries a write. */
  readonly ready?:(client:PublicHttpClient)=>Promise<boolean>;
}
interface Schema {readonly paths?:Readonly<Record<string,Readonly<Record<string,unknown>>>>}
async function reservePort():Promise<{port:number;release:()=>Promise<void>}> {
  assertFlowActive();
  const server=createServer();
  await new Promise<void>((resolve,reject)=>{server.once("error",reject);server.listen(0,"127.0.0.1",resolve)});
  const address=server.address();
  if(!address||typeof address==="string") throw new Error("No assigned loopback port");
  return {port:address.port,release:()=>new Promise<void>((resolve,reject)=>server.close(error=>error?reject(error):resolve()))};
}
/** The init options that choose the embedder and the tagger: `none` unless the case names an endpoint. */
function providerInitArgs(options:EngineOptions):string[] {
  const embedder=options.embedder;
  const tagger=options.oneironer;
  const endpointArgs=embedder?["--embedder","endpoint","--embedder-endpoint",embedder.endpoint,"--embedder-model-key",embedder.modelKey,
    "--embedder-model-id",embedder.modelId,"--dimensions",String(embedder.dimensions),
    ...("allowAll" in embedder.egress?["--embedder-egress-allow-all"]:["--embedder-egress-allow",embedder.egress.entityIds.join(",")])]:["--embedder","none"];
  const taggerArgs=tagger?["--oneironer","endpoint","--oneironer-url",tagger.url,"--oneironer-checkpoint-sha16",tagger.checkpointSha16,
    "--oneironer-label-count",String(tagger.labelCount),"--oneironer-mode",tagger.mode??"save"]:["--oneironer","none"];
  return [...endpointArgs,...taggerArgs];
}
/** Waits until a server process answers its real health handler (a startup gate answers "starting"). */
async function awaitHealth(url:string,server:ManagedProcess,artifacts:Artifacts,body:"ok"|"any"):Promise<void> {
  const publicClient=new PublicHttpClient(url,{timeoutMs:1000,artifacts,label:"health"});
  await awaitPublic(async()=>{
    if(!server.running) throw new Error(`Owned server exited: ${server.tail()}`);
    return publicClient.raw<{status?:string}>("GET","/api/health");
  },reply=>server.running&&reply.status===200&&(body==="any"||reply.body?.status==="ok"),{timeoutMs:LIMITS.readyMs,label:"owned server HTTP health",readiness:true});
}
/** Observes public state; only readiness transport failures are repeatable, never mutations. */
export async function awaitPublic<T>(read:()=>Promise<T>,ready:(value:T)=>boolean,options:{readonly timeoutMs?:number;readonly label:string;readonly readiness?:boolean}):Promise<T> {
  const budgetMs=options.timeoutMs??LIMITS.requestMs;
  const end=performance.now()+budgetMs;
  let last:unknown;
  let lastValue:unknown;
  const describe=(value:unknown)=>redactor.text((JSON.stringify(value instanceof Error?{name:value.name,message:value.message}:value)??"undefined"));
  while(performance.now()<end) {
    assertFlowActive();
    try {const value=await withDeadline(read(),Math.max(1,end-performance.now()),options.label);assertFlowActive();last=value;lastValue=value;if(ready(value)) return value}
    catch(error) {last=error;if(!options.readiness) {
      // A final-slice DeadlineError prints only its remainder; report the
      // original poll budget and the last real public state instead. Other
      // errors are immediate failures, not budget exhaustion, and pass through.
      if(error instanceof DeadlineError) throw new DeadlineError(`${options.label} deadline after ${budgetMs}ms poll budget; last public observation: ${describe(lastValue===undefined?error:lastValue)}`);
      throw error;
    }}
    const left=end-performance.now();
    if(left>0) await new Promise<void>(resolve=>setTimeout(resolve,Math.min(25,left)));
  }
  throw new Error(`${options.label} deadline after ${budgetMs}ms poll budget; last public observation: ${describe(lastValue===undefined?last:lastValue)}`);
}
export class EngineFixture {
  readonly artifacts:Artifacts;
  cli:CliClient;
  readonly sdk:SdkProcessDriver;
  readonly peers:EngineFixture[]=[];
  readonly devicePeers:DevicePeer[]=[];
  readonly url:string;
  pairedActor!:PairedActor;
  client!:PublicHttpClient;
  mcp!:McpClient;
  private server:ManagedProcess|undefined;
  /** Every server process this fixture launched, restarts included, for serverOutputHas. */
  private readonly launches:ManagedProcess[]=[];
  private schema:Schema|undefined;
  private closed=false;
  private disown:()=>void=()=>{};
  private constructor(readonly root:string,readonly build:BuildManifest,readonly env:Readonly<Record<string,string>>,readonly options:EngineOptions,port:number) {
    this.url=`http://127.0.0.1:${port}`;
    this.artifacts=new Artifacts(resolve(process.env.E2E_ARTIFACTS_DIR??resolve(root,"artifacts"),`${options.id??"engine"}-${secretHex(4)}`));
    this.cli=new CliClient(requireAsset(build,"cli"),root,env,this.artifacts);
    this.sdk=new SdkProcessDriver(build,root,env,this.artifacts);
  }
  static async start(options:EngineOptions):Promise<EngineFixture> {
    const startupId = await recordStart("stage",{method:"fixture.start",path:options.id??"engine"});
    let startupArtifacts:Artifacts|undefined;
    const stage = (method:string) => recordStart("stage",{method,path:options.id??"engine",startupId},startupArtifacts);
    const profile=process.env.E2E_PROFILE;
    if(profile&&profile!==options.profile) throw new BlockedDoor("Engine profile differs from scheduled profile");
    await stage("load-build");
    const build=await loadBuildManifest(options.profile);
    for(const capability of options.capabilities??[]) if(!build.capabilities.includes(capability)) throw new BlockedDoor(`waits on ${capability}`);
    const peers=options.peers??0;
    if(!Number.isInteger(peers)||peers<0) throw new TypeError("peers must be a nonnegative integer");
    if(peers>0&&process.env.E2E_FILE_SLOTS!=="2") throw new BlockedDoor("Multi-peer flows require a two-slot file");
    if(options.fastDims!==undefined&&(!Number.isInteger(options.fastDims)||options.fastDims<1)) throw new TypeError("fastDims must be a positive integer");
    await stage("temp-root");
    const root=await tempRoot(options.id??"engine");
    await stage("isolate-environment");
    const env=isolatedEnv(root,build.environment);
    for(const key of Object.keys(env)) if(key.startsWith("ONEIRON_")) delete env[key];
    env.ONEIRON_AUTH_SECRET=secretHex();redactor.add(env.ONEIRON_AUTH_SECRET);
    await mkdir(env.TMPDIR!,{recursive:true,mode:0o700});
    await stage("reserve-port");
    const reservation=await reservePort();
    const engine=new EngineFixture(root,build,env,options,reservation.port);
    startupArtifacts=engine.artifacts;
    let released=false;
    try {
      const config=resolve(root,"oneiron.toml");
      if(options.serverConfig&&/^\s*(host|port|vault_path|auth_secret|allow_unauthenticated)\s*=/m.test(options.serverConfig))
        throw new TypeError("EngineFixture owns isolation/auth fields; use an explicit unauthenticated case outside the default fixture");
      if(options.serverConfig?.trim()&&!options.serverConfig.trim().startsWith("[")) throw new TypeError("serverConfig is additional public TOML tables, not root keys");
      await stage("write-config");
      await writeFile(config,`host = "127.0.0.1"\nport = ${reservation.port}\n${options.fastDims===undefined?"":`fast_dims = ${options.fastDims}\n`}\n[keystore]\nbackend = "platform"\ndir = ${JSON.stringify(resolve(root,"keys"))}\n${options.serverConfig??""}`,{mode:0o600});
      await stage("cli-init");
      const init=await engine.cli.run(["init",resolve(root,"vault"),"--config",config,...providerInitArgs(options),...(options.initArgs??[])],undefined,LIMITS.readyMs,true,true);
      if(init.exitCode!==0) throw new CliError(init,"vault-init");
      if(options.embedderIdleIntervalMs!==undefined) {
        const written=await readFile(config,"utf8");
        if((written.match(/^\[embedder\]$/gm)??[]).length!==1) throw new TypeError("embedderIdleIntervalMs needs exactly one [embedder] table written by init");
        const policy=written.replace(/^\[embedder\]$/m,`[embedder]\nidle_interval_ms = ${options.embedderIdleIntervalMs}`);
        const parsed=Bun.TOML.parse(policy) as {embedder?:{idle_interval_ms?:number}};
        if(parsed.embedder?.idle_interval_ms!==options.embedderIdleIntervalMs) throw new TypeError("embedder idle interval did not land in [embedder]");
        await writeFile(config,policy,{mode:0o600});
      }
      await stage("cli-bootstrap");
      const bootstrap=await engine.cli.run(["token","bootstrap","--url",engine.url,"--config",config],undefined,LIMITS.readyMs,true);
      if(bootstrap.exitCode!==0) throw new CliError(bootstrap,"owner-bootstrap");
      const link=bootstrap.stdout.trim();redactor.add(link);
      const principalRef=new URL(link).hash.slice(1).split(".")[1];
      if(!principalRef||!/^[a-f0-9]{32}$/.test(principalRef)) throw new Error("Owner bootstrap returned no bound principal");
      await reservation.release();released=true;
      await stage("server-launch-and-health");
      await engine.launch();
      await stage("sdk-owner-pair");
      const paired=await engine.sdk.pair(link);
      engine.pairedActor=engine.actor(principalRef,"human",paired);
      engine.client=engine.pairedActor.client;engine.mcp=engine.pairedActor.mcp;engine.cli=engine.pairedActor.cli;
      await stage("schema-snapshot");
      const schema=await engine.client.request<Schema>("GET","/api/openapi.json");
      engine.schema=schema.body;
      await engine.artifacts.json("public-schema.json",{
        sha256:createHash("sha256").update(schema.bytes).digest("hex"),
        bytes:schema.bytes.byteLength,pathCount:Object.keys(schema.body.paths??{}).length,
      });
      await stage("public-readiness");
      if(options.ready) await awaitPublic(()=>options.ready!(engine.client),Boolean,{timeoutMs:LIMITS.readyMs,label:"requested public capabilities"});
      const configBytes=await readFile(config);
      await engine.artifacts.json("launch.json",{profile:options.profile,buildHead:build.head,url:engine.url,
        buildManifestSha256:process.env.E2E_BUILD_MANIFEST_SHA256,configSha256:createHash("sha256").update(configBytes).digest("hex"),
        config:redactor.text(configBytes.toString()),capabilities:options.capabilities??[]});
      engine.disown=ownResource(()=>engine.close());
      await stage("owner-policy");
      if(options.policy) await options.policy(engine);
      await stage("peers");
      for(let i=0;i<peers;i++) {
        const {peers:_count,...peerOptions}=options;
        engine.peers.push(await EngineFixture.start({...peerOptions,id:`${options.id??"engine"}-peer-${i}`,peers:0}));
      }
      await stage("fixture.ready");
      return engine;
    } catch(error) {
      if(!released) await reservation.release();
      await engine.close().catch(()=>{});throw error;
    }
  }
  private actor(principalRef:string,actorClass:PairedActor["actorClass"],paired:{credential:string;pin:unknown}):PairedActor {
    const client=new PublicHttpClient(this.url,{credential:paired.credential,artifacts:this.artifacts,label:`${actorClass}:${principalRef}`});
    const {bearer,seed}=credentialParts(paired.credential);
    const cli=new CliClient(requireAsset(this.build,"cli"),this.root,{...this.env,ONEIRON_URL:this.url,ONEIRON_TOKEN:bearer,ONEIRON_SECRET:bearer,ONEIRON_BINDING_KEY:seed},this.artifacts);
    return {principalRef,actorClass,...paired,client,mcp:new McpClient(client,this.options.surface),cli};
  }
  private async launch():Promise<void> {
    const server=await ManagedProcess.start([requireAsset(this.build,"server"),"serve","--config",resolve(this.root,"oneiron.toml")],
      {cwd:this.root,env:this.options.serverLog?{...this.env,RUST_LOG:this.options.serverLog}:this.env,label:`server-${secretHex(4)}`,artifacts:this.artifacts,diagnosticOutput:true});
    this.launches.push(server);
    this.server=server;
    await awaitHealth(this.url,server,this.artifacts,"any");
  }
  /** A second server process of this same logical vault, enrolled as a device of this fixture's
   * home through the public CLI: an empty peer vault is initialised (no bootstrap), the owner issues
   * a machine pairing link once the home's authority checkpoint is attested, the stopped peer runs
   * `device enrol` with the link on stdin, and the peer serves. Its client is the home owner's own
   * paired credential, admitted on the peer once authority has synced (self.actor answers 200);
   * the test mints nothing. Readiness means "serving and the owner admitted", not that the first
   * sync round finished: a case waits on the public read it asserts. `homeOrigin` is the origin the
   * link names, so the origin the device dials (a SyncLinkProxy url, to fault the link). The
   * server build must include the `mesh` feature (the shared artifact set does). */
  async startDevicePeer(options:DevicePeerOptions):Promise<DevicePeer> {
    if(this.closed||!this.pairedActor) throw new Error("startDevicePeer needs a started, owner-paired fixture");
    const root=await tempRoot(options.id);
    const env=isolatedEnv(root,this.build.environment);
    for(const key of Object.keys(env)) if(key.startsWith("ONEIRON_")) delete env[key];
    await mkdir(env.TMPDIR!,{recursive:true,mode:0o700});
    const reservation=await reservePort();
    let released=false;
    const peer=new DevicePeer(this,root,env,options,reservation.port);
    this.devicePeers.push(peer);
    try {
      if(options.serverConfig&&/^\s*(host|port|vault_path|auth_secret|allow_unauthenticated)\s*=/m.test(options.serverConfig))
        throw new TypeError("startDevicePeer owns isolation/auth fields");
      if(options.serverConfig?.trim()&&!options.serverConfig.trim().startsWith("[")) throw new TypeError("serverConfig is additional public TOML tables, not root keys");
      await writeFile(peer.config,`host = "127.0.0.1"\nport = ${reservation.port}\n${this.options.fastDims===undefined?"":`fast_dims = ${this.options.fastDims}\n`}\n[keystore]\nbackend = "platform"\ndir = ${JSON.stringify(resolve(root,"keys"))}\n${options.serverConfig??""}`,{mode:0o600});
      const local=new CliClient(requireAsset(this.build,"cli"),root,env,peer.artifacts);
      const init=await local.run(["init",peer.vault,"--config",peer.config,...providerInitArgs(this.options)],undefined,LIMITS.readyMs,true,true);
      if(init.exitCode!==0) throw new CliError(init,"device-peer-init");
      // A link can join an empty peer only when it carries the pin of an attested checkpoint.
      await awaitPublic(()=>this.client.request<{head:{current:boolean;shortfall:unknown}|null}>("GET","/v1/owner/checkpoint-policy/roots"),
        reply=>reply.body.head!==null&&reply.body.head.current===true&&reply.body.head.shortfall===null,
        {timeoutMs:LIMITS.readyMs,label:"home authority checkpoint attested"});
      const issued=await this.pairedActor.cli.run(["token","pair","--url",options.homeOrigin??this.url,"--principal-ref",this.pairedActor.principalRef,
        "--actor-class","human","--machine",options.ownership??"yours"],undefined,LIMITS.requestMs,true);
      if(issued.exitCode!==0) throw new CliError(issued,"device-pair-link");
      const link=issued.stdout.trim();redactor.add(link);
      if(new URL(link).hash.slice(1).split(".").length!==4) throw new Error("Machine pairing link carries no checkpoint pin");
      const enrolled=await local.run(["device","enrol",peer.vault,"--config",peer.config],`${link}\n`,LIMITS.readyMs,true);
      if(enrolled.exitCode!==0) throw new CliError(enrolled,"device-enrol");
      peer.enrolment=JSON.parse(enrolled.stdout) as DeviceEnrolment;
      if(peer.enrolment.checkpoint_pinned!==true) throw new Error("Device enrolment did not adopt the pinned checkpoint");
      await reservation.release();released=true;
      await peer.launch();
      return peer;
    } catch(error) {
      if(!released) await reservation.release();
      await peer.close().catch(()=>{});throw error;
    }
  }
  async pairActor(options:PairActorOptions):Promise<PairedActor> {
    const result=await this.pairedActor.cli.run(["token","pair","--url",this.url,"--principal-ref",options.principalRef,"--actor-class",options.actorClass,
      ...(options.scope?["--scope",options.scope.join(",")]:[]),...(options.lifetimeSeconds===undefined?[]:["--lifetime-secs",String(options.lifetimeSeconds)])],undefined,LIMITS.requestMs,true);
    if(result.exitCode!==0) throw new CliError(result,"actor-pair");
    const link=result.stdout.trim();redactor.add(link);
    return this.actor(options.principalRef,options.actorClass,await this.sdk.pair(link));
  }
  /** Only public receipt reads, never a private job drain or an internal commit counter: resolves `call:` refs through `vault.receipts.get` and any other ref only as a row of the `vault.receipts` page (gate-ledger receipts); `witness:` and `put:` refs are write markers, not receipt rows, and never resolve here, so read the written entity back through `vault.get` instead. */
  async awaitReceipt(ref:string,timeoutMs:number=LIMITS.requestMs):Promise<unknown> {
    if(ref.startsWith("call:")) return awaitPublic(()=>this.client.call("vault.receipts.get",{receipt_ref:ref}),value=>value!==null,
      {timeoutMs,label:`receipt ${ref}`});
    return awaitPublic(()=>this.client.call("vault.receipts",{limit:1000}),page=>page.receipts.some(row=>row.receipt_ref===ref),
      {timeoutMs,label:`receipt ${ref}`}).then(page=>page.receipts.find(row=>row.receipt_ref===ref));
  }
  async websocket(actor:PairedActor=this.pairedActor):Promise<WsClient> {return WsClient.connect(this.url,actor.credential)}
  /** Negative leak scan over the raw stdout and stderr of every server process this fixture launched,
   * restarts included. It scans in memory only and never persists or returns output. Only a closed
   * fixture has read every line its processes wrote, so call it after `close()`. A case asserts
   * `{found:false,truncated:false}`: `truncated` means a stream outgrew its window, so absence is unproved. */
  serverOutputHas(values:readonly string[]):{found:boolean;truncated:boolean} {
    if(!this.closed) throw new Error("serverOutputHas reads complete output only: close the fixture first");
    const scans=this.launches.map(server=>server.outputHas(values));
    if(scans.length===0) throw new Error("serverOutputHas found no server launch to scan");
    return {found:scans.some(scan=>scan.found),truncated:scans.some(scan=>scan.truncated)};
  }
  /** OpenAPI covers non-facade endpoints; generated facade types are the facade contract. */
  async requireHttpDoor(path:string,method:string):Promise<void> {
    if(!this.schema) this.schema=(await this.client.request<Schema>("GET","/api/openapi.json")).body;
    if(!this.schema.paths?.[path]?.[method.toLowerCase()]) throw new BlockedDoor(`waits on ${method} ${path}`);
  }
  async restart():Promise<void> {
    if(this.closed) throw new Error("Cannot restart closed fixture");
    await this.server?.stop();await this.launch();
    this.schema=undefined;
    await this.client.call("vault.receipts",{limit:1});
  }
  /** Caller first observes a public receipt, ACK or provider barrier; this method invents none. */
  async kill():Promise<void> {await this.server?.stop("SIGKILL")}
  async close(options:{readonly retainVault?:boolean}={}):Promise<void> {
    if(this.closed) return;this.closed=true;this.disown();
    const results=await Promise.allSettled([...this.devicePeers.map(peer=>peer.close()),...this.peers.map(peer=>peer.close(options))]);
    await this.server?.stop();this.mcp?.close();
    if(!options.retainVault) await rm(this.root,{recursive:true,force:true});
    else if(process.env.E2E_TEMP_ROOT) await writeFile(resolve(process.env.E2E_TEMP_ROOT,"retain-vaults"),"explicit local retention\n",{mode:0o600});
    const failure=results.find(result=>result.status==="rejected");if(failure?.status==="rejected") throw failure.reason;
  }
}
export interface DevicePeerOptions {
  readonly id:string;
  /** The machine's ownership on the pairing link; default "yours". */
  readonly ownership?:"yours"|"work_school"|"rented";
  /** The origin the pairing link names, so the origin the device dials for sync; default the home's url. */
  readonly homeOrigin?:string;
  /** Additional public TOML tables for the peer's config. */
  readonly serverConfig?:string;
  readonly serverLog?:string;
}
/** `device enrol`'s stdout: the record it wrote and what it shows for anchoring. */
export interface DeviceEnrolment {
  readonly home_machine:string;readonly home_node_id:string;readonly home_url:string;readonly checkpoint_pinned:boolean;
  readonly re_paired:boolean;readonly record:string;readonly credential_file:string;readonly [field:string]:unknown;
}
export class DevicePeer {
  readonly url:string;
  readonly artifacts:Artifacts;
  readonly config:string;
  readonly vault:string;
  /** The home owner's paired credential, pointed at the peer. */
  readonly client:PublicHttpClient;
  /** The home owner's remote CLI (api calls), pointed at the peer; never the peer's local commands. */
  readonly cli:CliClient;
  enrolment!:DeviceEnrolment;
  private server:ManagedProcess|undefined;
  private closed=false;
  constructor(readonly home:EngineFixture,readonly root:string,private readonly env:Readonly<Record<string,string>>,readonly options:DevicePeerOptions,port:number) {
    this.url=`http://127.0.0.1:${port}`;
    this.config=resolve(root,"oneiron.toml");this.vault=resolve(root,"vault");
    this.artifacts=new Artifacts(resolve(process.env.E2E_ARTIFACTS_DIR??resolve(root,"artifacts"),`${options.id}-${secretHex(4)}`));
    const owner=home.pairedActor;
    this.client=new PublicHttpClient(this.url,{credential:owner.credential,artifacts:this.artifacts,label:`device-peer:${owner.principalRef}`});
    const {bearer,seed}=credentialParts(owner.credential);
    this.cli=new CliClient(requireAsset(home.build,"cli"),root,{...env,ONEIRON_URL:this.url,ONEIRON_TOKEN:bearer,ONEIRON_SECRET:bearer,ONEIRON_BINDING_KEY:seed},this.artifacts);
  }
  /** Serves the enrolled peer, then waits until it admits the home owner's credential. */
  async launch():Promise<void> {
    const server=await ManagedProcess.start([requireAsset(this.home.build,"server"),"serve","--config",this.config],
      {cwd:this.root,env:this.options.serverLog?{...this.env,RUST_LOG:this.options.serverLog}:this.env,label:`device-peer-server-${secretHex(4)}`,artifacts:this.artifacts,diagnosticOutput:true});
    this.server=server;
    await awaitHealth(this.url,server,this.artifacts,"ok");
    const owner=this.home.pairedActor.principalRef;
    // 401 until the owner's mint reaches the peer's authority view; any other answer is a failure.
    await awaitPublic(async()=>{
      const reply=await this.client.raw<{actor_ref?:string;actor_class?:string}>("POST","/v1/core/facade/self.actor",{},{"x-oneiron-invocation":secretHex(16)});
      if(reply.status!==200&&reply.status!==401&&reply.status!==503) throw new Error(`device peer self.actor answered ${reply.status}`);
      return reply;
    },reply=>reply.status===200&&reply.body.actor_ref===owner&&reply.body.actor_class==="human",
      {timeoutMs:LIMITS.readyMs,label:"device peer admits the home owner"});
  }
  async kill():Promise<void> {await this.server?.stop("SIGKILL")}
  async restart():Promise<void> {
    if(this.closed) throw new Error("Cannot restart a closed device peer");
    await this.server?.stop();await this.launch();
  }
  async close():Promise<void> {
    if(this.closed) return;this.closed=true;
    await this.server?.stop();
    await rm(this.root,{recursive:true,force:true});
  }
}
export type PublicReceiptInput=FacadeInput<"vault.receipts">;
export type PublicReceipt=FacadeResult<"vault.receipts">["receipts"][number];
