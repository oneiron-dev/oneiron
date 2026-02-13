# oneiron-db Deployment & Infrastructure

> Split from [SCHEMA-DESIGN.md](./SCHEMA-DESIGN.md). Covers deployment platform, vault placement, ML infrastructure, and operational concerns.
> These decisions are outside the Rust crate — they inform how the crate is deployed and what services surround it.

---

## Multi-Vault Deployment

### Architecture: One LMDB Environment Per Vault

Each vault is a directory with its own LMDB files:

```
/data/oneiron/vaults/
├── vault_abc123/
│   ├── data.mdb
│   └── lock.mdb
├── vault_def456/
│   ├── data.mdb
│   └── lock.mdb
└── vault_ghi789/
    ├── data.mdb
    └── lock.mdb
```

**Why NOT a shared environment:**
- LMDB has a single-writer lock per environment. Shared env = vault A's write blocks vault B.
  Separate envs = all vaults write concurrently.
- Corruption in one vault would take down all vaults.
- Can't easily delete/move/backup individual vaults.

### Resource Cost

| Resource | Per Vault | 100 Vaults | 1000 Vaults | Limit |
|----------|-----------|------------|-------------|-------|
| Virtual memory | 1-8GB | 100-800GB | 1-8TB | 128TB on 64-bit (free) |
| Physical RAM | Only hot pages | OS manages via page cache | Cold vaults ≈ 0 RAM | Machine RAM |
| File descriptors | 2 | 200 | 2000 | ulimit (65536 default) |

Virtual memory is free on 64-bit. A vault not accessed for hours uses ~0 physical RAM.

### VaultManager

```rust
pub struct VaultManager {
    base_path: PathBuf,
    open_vaults: HashMap<String, Vault>,
    default_config: VaultConfig,
}

impl VaultManager {
    pub fn new(base_path: impl AsRef<Path>, default_config: VaultConfig) -> Result<Self>;
    pub fn get(&mut self, vault_id: &str) -> Result<&Vault>;
    pub fn get_with_config(&mut self, vault_id: &str, config: VaultConfig) -> Result<&Vault>;
    pub fn close(&mut self, vault_id: &str) -> Result<()>;
    pub fn destroy(&mut self, vault_id: &str) -> Result<()>;
    pub fn list(&self) -> Result<Vec<String>>;
    pub fn evict_idle(&mut self, cutoff: std::time::Instant) -> usize;
    pub fn export(&mut self, vault_id: &str) -> Result<PathBuf>;
    pub fn import(&mut self, vault_id: &str, source_path: &Path) -> Result<()>;
    pub fn stats(&self, vault_id: &str) -> Result<VaultStats>;
}

pub struct VaultStats {
    pub entity_count: u64,
    pub vector_count: u64,
    pub edge_count: u64,
    pub disk_bytes: u64,
    pub dimensions: usize,
    pub embedding_model: Option<String>,
}
```

---

## Deployment Platform: Fly.io Machines (v1)

**Decision: Fly Machines, not Kubernetes.**

| Factor | Fly Machines | Kubernetes | Cloudflare DO |
|---|---|---|---|
| Local disk + mmap | Yes (NVMe volumes) | Complex (network-attached EBS) | No (KV only) |
| Scale-to-zero | Native (`stop/start`) | Bolt-on (KEDA) | Native |
| Wake time | ~315ms | 2-10s | ~0ms |
| Rust + LMDB fit | Perfect | LMDB mmap over network = 10-30x slower | No filesystem |
| Ops complexity | Near zero | Significant (cluster mgmt) | Lowest but incompatible |
| Cost (1K vaults) | ~$150/mo | ~$143/mo + ops | N/A |

**Why not K8s:** LMDB is memory-mapped. K8s PersistentVolumeClaims are network-attached storage (EBS/PD). Every page fault becomes a network round-trip instead of a local disk read. For HNSW traversal (random reads), this is 10-30x slower.

**Why not Cloudflare DO:** No filesystem, no mmap, 128MB memory limit, JS/Wasm only. Architecturally incompatible with LMDB.

**Why not big clouds directly:** AWS Lambda/GCP Cloud Run have no persistent local storage. EC2/GCE don't scale to zero. Fly is uniquely positioned: Firecracker microVMs + local NVMe volumes + scale-to-zero + per-machine routing.

**Escape hatch:** The Rust crate is platform-agnostic (opens LMDB at a path). If Fly becomes unsuitable, containerize and move to Hetzner+Nomad, self-hosted Firecracker, or K8s with local SSD node pools. No code changes.

**Not Azure:** Aggressive content filtering policy. Unsuitable for a personal memory product storing intimate conversations.

---

## Vault Placement: 1 Machine Per Vault (v1)

**Decision: One Fly Machine + volume per vault. Two states only.**

```
RUNNING:  Active session. Machine is awake, serving real-time.
          Compute: ~$0.002/hr

SLEEPING: No active session. Machine scales to zero automatically.
          Compute: $0
          Storage: $0.15/month (1GB min Fly volume)
          Wake time: ~315ms (Fly proxy auto-starts on request)
```

No tier management, no bin-packing, no routing table for v1. Fly proxy handles wake-on-request natively.

**Cost at scale:**

| Users | Monthly Storage | Revenue (at $10/mo) | Storage % |
|---|---|---|---|
| 1K | $150 | $10K | 1.5% |
| 10K | $1,500 | $100K | 1.5% |
| 100K | $15,000 | $1M | 1.5% |

At $0.15/vault/month, storage is always ~1.5% of revenue. Negligible.

**Paying users stay warm (sleeping) forever.** $0.15/month per vault vs $10+/month revenue = no reason to archive.

**Region placement:** On account creation, detect user's region from first request. Create machine + volume in nearest Fly region (cdg, nrt, iad, etc.). All subsequent requests route there.

**When to revisit (v2+):**
- 1M+ free-tier users → cold storage (R2, `vault_{id}.tar.zst`) for users inactive 6+ months
- Pre-warm on signal: push notification delivered, device sync ping, time-of-day patterns
- Pack free-tier sleeping vaults onto shared machines for storage savings

---

## Migration Mechanics (Retained for Future Use)

LMDB files are portable (same architecture). Moving a vault:

```
1. QUIESCE   — stop writes, wait for in-flight txn, close LMDB env
2. TRANSFER  — tar+zstd → R2 → target machine → decompress
               OR direct rsync between machines
3. VERIFY    — open on target, check hnsw_meta["count"]
4. CUTOVER   — update routing table (Convex), new requests go to target
5. CLEANUP   — delete from source
```

**Transfer times (1 Gbps network):**

| Vault Size | Compressed | Transfer |
|-----------|-----------|----------|
| 15MB (1K entities) | ~6MB | <1s |
| 150MB (10K entities) | ~60MB | <1s |
| 750MB (50K entities) | ~300MB | ~3s |
| 2.5GB (50K @ 4096-dim) | ~1GB | ~8s |

### Cold Storage Format (v2)

```
vault_{id}.tar.zst contents:
├── data.mdb
└── manifest.json

manifest.json:
{
  "vaultId": "abc123",
  "archivedAt": 1739456789000,
  "entityCount": 12345,
  "diskBytes": 157286400,
  "dimensions": 1024,
  "embeddingModel": "qwen3-8b-v1",
  "oneironDbVersion": "0.1.0",
  "lmdbVersion": "0.9.33"
}
```

### What oneiron-db (Rust Crate) Provides

The crate stays simple. Migration-friendly requirements:
1. **Clean shutdown** — `Drop` impl closes LMDB env cleanly
2. **No in-process state** — everything durable is in LMDB, no in-memory caches lost on migration
3. **VaultManager.export()/import()** — convenience for archive/restore
4. **Vault.stats()** — for manifest generation and monitoring

All tier management, migration orchestration, routing, and packing is control plane (Convex + Fly API).

---

## ML Infrastructure (Not in Rust Crate)

### Architecture: 1 Modal GPU Per Fly Region

NER and embedding inference run on a shared Modal GPU service, not in the vault process.

```
              Region: US-East

┌──────────────────────────────────┐
│  Modal GPU (A10G, keep_warm=1)   │
│                                  │
│  ┌────────────┐ ┌─────────────┐  │
│  │ NER 0.6B   │ │ Embed 8B    │  │
│  │ int8       │ │ int8        │  │
│  └────────────┘ └─────────────┘  │
└──────────▲───────────────────────┘
           │  gRPC / HTTP (~10-20ms)
     ┌─────┴─────┬─────────────┐
     │           │             │
┌────┴───┐ ┌────┴───┐  ┌──────┴─┐
│vault-01│ │vault-02│  │vault-N │
│  LMDB  │ │  LMDB  │  │  LMDB  │
└────────┘ └────────┘  └────────┘
     Fly Machines (same region)
```

### NER Model

Custom Qwen3-0.6B converted from decoder to encoder (LLM2Vec process with improved training data).

- Base: Qwen3-0.6B (multilingual, strong CJK/Arabic/Cyrillic)
- Architecture: Decoder → encoder via LLM2Vec (enable bidirectional attention, MNTP training)
- Training: SFT on entity types (PERSON, PLACE, SKILL, TOPIC, EVENT, etc.)
- Output: entity spans with types and scores
- Size: ~600MB int8

### Embedding Model

Qwen3-Embedding-8B — MTEB rank #3 (score 70.58).

| Model | MTEB Rank | Mean Score | Retrieval | Params | Dim |
|---|---|---|---|---|---|
| Qwen3-Embedding-8B | #3 | 70.58 | 70.88 | 7.6B | 4096 |
| Qwen3-Embedding-4B | #5 | 69.45 | 69.60 | 4.0B | 2560 |
| Qwen3-Embedding-0.6B | #8 | 64.34 | 64.65 | 0.6B | 1024 |

8B over 0.6B because retrieval quality is the product's core value. +6 points on retrieval is the difference between finding the right memory and not.

### GPU Sizing

A10G (24GB VRAM):
```
Qwen3-Embedding-8B int8:  ~8GB
Qwen3-NER-0.6B int8:      ~600MB
Tokenizer + overhead:      ~400MB
Total:                     ~9GB / 24GB (38% utilized)
```

Both models fit on one A10G with room to spare.

### Cost

| Setup | Monthly | Notes |
|---|---|---|
| 1 region (keep_warm=1) | ~$800 | + autoscale on demand |
| 3 regions (US/EU/Asia) | ~$2,400 | + autoscale |
| At $10/mo, 10K users = $100K revenue | | ML infra = 2.4% |

### Latency (Write Path)

```
Vault (Fly) → Modal GPU (same region):  ~10-20ms network
NER inference (0.6B on GPU):             ~2-3ms
Embedding inference (8B on GPU):         ~10-15ms
Total per write:                         ~25-35ms
```

### Inference Runtime: Candle → Luminal (Rust, CUDA)

Both models compiled with Candle (HuggingFace Rust ML framework) targeting CUDA. Not Python/PyTorch.

| | Python + PyTorch | Rust + Candle (CUDA) |
|---|---|---|
| Container size | ~5-8GB | ~50-100MB |
| Modal cold start | 20-40s | 3-5s |
| Python overhead | GIL, dispatch | None |

5-10x faster cold start on Modal = more aggressive auto-scaling, lower cost.

**Luminal exploration (active).** Evaluating Luminal as alternative to Candle for graph-level compilation:

| Metric | Candle (eager) | Luminal (compiled) |
|---|---|---|
| Kernel launches | ~200 per forward | ~20-40 (fused) |
| Peak VRAM | ~9GB | ~6-7GB (could fit on T4) |
| Throughput | ~15-30 req/s | ~30-60 req/s |
| GPU needed | A10G ($1.10/hr) | Possibly T4 ($0.60/hr) |

If Luminal reduces VRAM enough to fit on T4: ~$1,100/month savings across 3 regions. Also unlocks Metal backend for on-device inference (Mac GPU).

### Dreamer Batch Jobs

Async deep extraction (not latency-sensitive) runs on Salad (cheap consumer GPUs):

| Workload | Platform | Model | Cost |
|---|---|---|---|
| Per-message NER + embedding | Modal (A10G) | 0.6B NER + 8B embed | $800-2,400/mo |
| Dreamer deep extraction | Salad | Qwen 8B SFT (decoder) | ~$5-20/night |
| SFT training | Modal | Various | One-time / periodic |

### Progressive Disclosure for Skills

Skills as entities support progressive disclosure through chunking and edge weights:

```
SKILL entity (root)
  ├── --[has_content, w=1.0]--> summary chunk
  ├── --[has_content, w=0.7]--> basic usage chunk
  ├── --[has_content, w=0.4]--> advanced patterns chunk
  └── --[has_content, w=0.3]--> edge cases chunk
```

PPR walks high-weight edges first → retrieval naturally returns summary before details. Dreamer adjusts edge weights based on usage frequency (agent keeps needing advanced chunk → weight increases). No schema changes — this is a chunking convention + edge weight strategy.
