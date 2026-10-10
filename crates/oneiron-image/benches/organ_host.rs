//! The organ host's four measures (design page section 7), on synthetic
//! images only: `cargo bench -p oneiron-image --bench organ_host`.
//!
//! 1. Added cost of a small op: `image.crop` through the host and the
//!    organ process, against the same op called in this process.
//! 2. Read throughput of a 100 MiB and a 1 GiB blob: a cached region, a cold
//!    region (copied out of the vault and checked first), and the same bytes
//!    copied over the socket.
//! 3. Cold start (spawn to `hello_ack`) and the first op after an unload.
//! 4. Resident memory of a warm organ, idle and after one export.
//!
//! Run it on one quiet host; it prints the host and its load beside the table.

#[cfg(unix)]
mod bench {
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

    use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
    use oneiron::registry::ENTITY_TYPE_PERSON;
    use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
    use oneiron_image::{ImageOrgan, VERB_CROP, VERB_EXPORT, VERB_OPEN};
    use oneiron_organ_host::{CallClass, HostConfig, OrganCall, OrganHost, OrganInput, OrganSpec};
    use oneiron_organ_protocol::{CallContext, InputBytes, Limits, Organ, TypedBody, VERB_TOUCH};
    use rmpv::Value;

    const ORGAN: &str = env!("CARGO_BIN_EXE_oneiron-image-organ");
    const BIN: &str = "application/octet-stream";
    const PNG: &str = "image/png";
    const MIB: u64 = 1024 * 1024;

    fn at(time: u64) -> TimeRange {
        TimeRange {
            start: time,
            end: time,
        }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        vault: Vault,
        actor: EntityId,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let mut config = VaultConfig::device();
            config.map_size = 4 * 1024 * MIB as usize;
            config.dimensions = 4;
            config.embedding_model = None;
            let vault = Vault::open_unseeded_for_test(dir.path(), config).expect("vault");
            let actor = EntityId::now();
            vault
                .put_entity(&actor, ENTITY_TYPE_PERSON, at(1), 1, b"bench")
                .expect("actor");
            Self {
                _dir: dir,
                vault,
                actor,
            }
        }

        fn put(&self, bytes: &[u8], media_type: &str) -> OrganInput {
            let artifact = EntityId::now();
            self.vault
                .put_blob_artifact(
                    &artifact,
                    &BlobArtifactBody::new("bench", media_type),
                    at(1),
                    1,
                )
                .expect("artifact");
            let version = self
                .vault
                .append_blob_artifact_version(
                    &artifact,
                    bytes,
                    &BlobVersionProvenance::UserUpload,
                    WriteActor::new(self.actor, EdgeActorClass::Human),
                    at(2),
                    2,
                )
                .expect("version");
            OrganInput {
                artifact,
                version: version.version,
            }
        }
    }

    fn spec(memory_bytes: u64, max_call_frame: u32) -> OrganSpec {
        let mut spec = OrganSpec::first_party("image", ORGAN);
        spec.verbs = [VERB_OPEN, VERB_CROP, VERB_EXPORT, VERB_TOUCH]
            .map(String::from)
            .into();
        spec.media_types = vec![PNG.to_owned(), BIN.to_owned()];
        spec.memory_bytes = memory_bytes;
        spec.max_call_frame = max_call_frame;
        spec
    }

    fn host_with(config: HostConfig, spec: OrganSpec) -> OrganHost {
        let host = OrganHost::new(config);
        host.install(spec);
        host
    }

    fn call(
        verb: &str,
        args: Value,
        body: Option<TypedBody>,
        inputs: Vec<OrganInput>,
    ) -> OrganCall {
        OrganCall {
            organ: "image".into(),
            verb: verb.into(),
            schema: 1,
            args,
            body,
            inputs,
            class: CallClass::Interactive,
            deadline: Duration::from_secs(120),
            grant: "bench".into(),
        }
    }

    fn crop_args() -> Value {
        Value::Map(vec![
            ("x".into(), 1.into()),
            ("y".into(), 1.into()),
            ("w".into(), 62.into()),
            ("h".into(), 62.into()),
        ])
    }

    /// A 64x64 gradient PNG, made here.
    fn small_png() -> Vec<u8> {
        let mut out = Vec::new();
        let pixels: Vec<u8> = (0..64u32 * 64)
            .flat_map(|i| [(i % 251) as u8, (i % 13) as u8, (i % 7) as u8, 255])
            .collect();
        image::ImageEncoder::write_image(
            image::codecs::png::PngEncoder::new(&mut out),
            &pixels,
            64,
            64,
            image::ExtendedColorType::Rgba8,
        )
        .expect("png");
        out
    }

    fn percentile(sorted: &[Duration], pct: usize) -> Duration {
        let at = (sorted.len() * pct / 100).min(sorted.len().saturating_sub(1));
        sorted.get(at).copied().unwrap_or_default()
    }

    fn micros(duration: Duration) -> f64 {
        duration.as_secs_f64() * 1e6
    }

    fn millis(duration: Duration) -> f64 {
        duration.as_secs_f64() * 1e3
    }

    fn timed(runs: usize, mut f: impl FnMut()) -> Vec<Duration> {
        let mut times: Vec<Duration> = (0..runs)
            .map(|_| {
                let started = Instant::now();
                f();
                started.elapsed()
            })
            .collect();
        times.sort();
        times
    }

    fn load() -> String {
        std::fs::read_to_string("/proc/loadavg").map_or_else(
            |_| "unknown".into(),
            |line| {
                line.split_whitespace()
                    .take(3)
                    .collect::<Vec<_>>()
                    .join(" ")
            },
        )
    }

    fn host_name() -> String {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map_or_else(|_| "unknown".into(), |name| name.trim().to_owned())
    }

    fn rss_kib(pid: u32) -> Option<u64> {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        status
            .lines()
            .find_map(|line| line.strip_prefix("VmRSS:"))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|kib| kib.parse().ok())
    }

    /// Row 1: `image.crop` on a body, through the host and in this process.
    fn small_op(fixture: &Fixture, runs: usize) {
        let host = host_with(HostConfig::default(), spec(512 * MIB, 64 * MIB as u32));
        let source = fixture.put(&small_png(), PNG);
        let opened = host
            .call(
                &fixture.vault,
                call(VERB_OPEN, Value::Nil, None, vec![source]),
            )
            .expect("open");
        let body = opened.body.expect("body");
        let through_host = |body: &TypedBody| {
            host.call(
                &fixture.vault,
                call(VERB_CROP, crop_args(), Some(body.clone()), Vec::new()),
            )
            .expect("crop")
        };
        for _ in 0..200 {
            through_host(&body);
        }
        let hosted = timed(runs, || {
            std::hint::black_box(through_host(&body));
        });
        let organ = ImageOrgan::default();
        let limits = Limits {
            threads: 2,
            memory_bytes: 512 * MIB,
            max_call_frame: 64 * MIB as u32,
            max_reply_frame: 64 * MIB as u32,
        };
        let args = crop_args();
        let in_process = || {
            let cancel = AtomicBool::new(false);
            let inputs: [InputBytes; 0] = [];
            organ
                .call(&CallContext::new(
                    VERB_CROP,
                    1,
                    &args,
                    Some(&body),
                    &inputs,
                    limits,
                    &cancel,
                ))
                .expect("crop in process")
        };
        for _ in 0..200 {
            in_process();
        }
        let local = timed(runs, || {
            std::hint::black_box(in_process());
        });
        let row = |name: &str, times: &[Duration]| {
            println!(
                "| 1 | {name} | {:.1} µs | {:.1} µs |",
                micros(percentile(times, 50)),
                micros(percentile(times, 99))
            );
        };
        row("crop through host + organ process", &hosted);
        row("crop in process", &local);
        println!(
            "| 1 | added cost (p50 and p99 differences) | {:.1} µs | {:.1} µs |",
            micros(percentile(&hosted, 50)) - micros(percentile(&local, 50)),
            micros(percentile(&hosted, 99)) - micros(percentile(&local, 99)),
        );
    }

    fn touch(host: &OrganHost, fixture: &Fixture, input: OrganInput) -> Duration {
        let started = Instant::now();
        host.call(
            &fixture.vault,
            call(VERB_TOUCH, Value::Nil, None, vec![input]),
        )
        .expect("touch");
        started.elapsed()
    }

    fn gib_per_s(bytes: u64, time: Duration) -> f64 {
        bytes as f64 / (1024.0 * 1024.0 * 1024.0) / time.as_secs_f64()
    }

    /// Row 2: `organ.touch` over a blob: a cached region, a cold region, and
    /// a socket copy.
    fn throughput(fixture: &Fixture, mib: u64, runs: usize) {
        let bytes: Vec<u8> = (0..mib * MIB).map(|i| (i % 251) as u8).collect();
        let input = fixture.put(&bytes, BIN);
        let len = bytes.len() as u64;
        drop(bytes);
        let regions = host_with(
            HostConfig {
                region_cache_bytes: 2 * len,
                ..HostConfig::default()
            },
            spec(512 * MIB, 64 * MIB as u32),
        );
        regions.warm("image").expect("warm");
        let mut cold = Vec::new();
        let mut cached = Vec::new();
        for _ in 0..runs {
            regions.clear_regions();
            cold.push(touch(&regions, fixture, input));
            cached.push(touch(&regions, fixture, input));
        }
        let socket = host_with(
            HostConfig {
                inline_max_bytes: usize::MAX,
                ..HostConfig::default()
            },
            spec(
                4 * len + 512 * MIB,
                u32::try_from(len + 64 * MIB).unwrap_or(u32::MAX),
            ),
        );
        socket.warm("image").expect("warm");
        let copied: Vec<Duration> = (0..runs).map(|_| touch(&socket, fixture, input)).collect();
        for (name, mut times) in [
            ("cached region", cached),
            ("cold region (vault copy + check first)", cold),
            ("socket copy", copied),
        ] {
            times.sort();
            let median = percentile(&times, 50);
            println!(
                "| 2 | {mib} MiB, {name} | {:.2} GiB/s | {:.1} ms |",
                gib_per_s(len, median),
                millis(median)
            );
        }
    }

    /// Row 3: spawn to `hello_ack`, and the first op after an unload.
    fn cold_start(fixture: &Fixture, runs: usize) {
        let host = host_with(HostConfig::default(), spec(512 * MIB, 64 * MIB as u32));
        let source = fixture.put(&small_png(), PNG);
        let body = host
            .call(
                &fixture.vault,
                call(VERB_OPEN, Value::Nil, None, vec![source]),
            )
            .expect("open")
            .body
            .expect("body");
        let mut spawn = Vec::new();
        let mut first = Vec::new();
        for _ in 0..runs {
            host.unload("image");
            spawn.push(host.warm("image").expect("warm"));
            host.unload("image");
            let started = Instant::now();
            host.call(
                &fixture.vault,
                call(VERB_CROP, crop_args(), Some(body.clone()), Vec::new()),
            )
            .expect("crop");
            first.push(started.elapsed());
        }
        spawn.sort();
        first.sort();
        for (name, times) in [
            ("cold start, spawn to hello_ack", &spawn),
            ("first crop after unload", &first),
        ] {
            println!(
                "| 3 | {name} | {:.1} ms | {:.1} ms |",
                millis(percentile(times, 50)),
                millis(percentile(times, 99))
            );
        }
    }

    /// Row 4: resident memory of a warm organ.
    fn memory(fixture: &Fixture) {
        let host = host_with(HostConfig::default(), spec(512 * MIB, 64 * MIB as u32));
        host.warm("image").expect("warm");
        let pid = host
            .status("image")
            .and_then(|status| status.pid)
            .expect("pid");
        let idle = rss_kib(pid);
        let source = fixture.put(&small_png(), PNG);
        let body = host
            .call(
                &fixture.vault,
                call(VERB_OPEN, Value::Nil, None, vec![source]),
            )
            .expect("open")
            .body;
        let export = Value::Map(vec![("format".into(), "png".into())]);
        host.call(
            &fixture.vault,
            call(VERB_EXPORT, export, body, vec![source]),
        )
        .expect("export");
        let after = rss_kib(pid);
        let show = |kib: Option<u64>| {
            kib.map_or_else(
                || "n/a".to_owned(),
                |kib| format!("{:.1} MiB", kib as f64 / 1024.0),
            )
        };
        println!("| 4 | RSS, idle after handshake | {} | |", show(idle));
        println!(
            "| 4 | RSS, after open + export of a 64x64 PNG | {} | |",
            show(after)
        );
    }

    pub(super) fn run() {
        let quick = std::env::var_os("ORGAN_BENCH_QUICK").is_some();
        let fixture = Fixture::new();
        println!("host {} · load before {}", host_name(), load());
        println!();
        println!("| # | measure | p50 / rate | p99 / median |");
        println!("|---|---|---|---|");
        small_op(&fixture, if quick { 200 } else { 2000 });
        throughput(&fixture, 100, if quick { 2 } else { 5 });
        if !quick {
            throughput(&fixture, 1024, 3);
        }
        cold_start(&fixture, if quick { 10 } else { 50 });
        memory(&fixture);
        println!();
        println!("load after {}", load());
    }
}

fn main() {
    #[cfg(unix)]
    bench::run();
}
