//! Actual WebAssembly capability fixture, using the host's preinstalled Node runtime.
use super::*;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

struct Bridge {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}
impl Bridge {
    fn call(&mut self, verb: &str, ms: u32) -> anyhow::Result<u64> {
        writeln!(self.input, "{}", serde_json::json!({"verb":verb,"ms":ms}))?;
        self.input.flush()?;
        let mut reply = String::new();
        anyhow::ensure!(self.output.read_line(&mut reply)? > 0, "WASM host exited");
        serde_json::from_str::<serde_json::Value>(&reply)?["value"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("invalid WASM result"))
    }
}
impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
struct WebAssemblyBackend(Mutex<Bridge>);
impl SandboxBackend for WebAssemblyBackend {
    type Listener = u64;
    fn listener(&mut self) -> anyhow::Result<u64> {
        self.0.get_mut().unwrap().call("listener", 0)
    }
    fn ready(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.0.get_mut().unwrap().call("ready", 0)? == 1,
            "not ready"
        );
        Ok(())
    }
    fn secret(&mut self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        anyhow::ensure!(name == "fixture", "unknown fixture secret");
        Ok(Zeroizing::new(vec![u8::try_from(
            self.0.get_mut().unwrap().call("secret", 0)?,
        )?]))
    }
    fn stop(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.0.get_mut().unwrap().call("on_stop", 0)? == 0,
            "not stopped"
        );
        Ok(())
    }
    fn limits(&self) -> HostLimits {
        HostLimits {
            memory_bytes: self.0.lock().unwrap().call("limits", 0).unwrap() * 1024 * 1024,
            cpu_millis_per_second: 1000,
        }
    }
    fn sleep(&mut self, next: Option<SystemTime>) -> HostFuture<'_> {
        Box::pin(async move {
            let millis = next
                .ok_or_else(|| anyhow::anyhow!("fixture requires deadline"))?
                .duration_since(SystemTime::now())
                .unwrap_or_default()
                .as_nanos()
                .div_ceil(1_000_000);
            anyhow::ensure!(millis <= 100, "fixture deadline bound");
            let ready = self
                .0
                .get_mut()
                .unwrap()
                .call("idle", u32::try_from(millis)?)?;
            anyhow::ensure!(ready == 1, "idle exited or lost module state");
            Ok(())
        })
    }
}
#[tokio::test]
async fn real_wasm_guest_drives_six_verbs_and_sleeps_without_exit() -> anyhow::Result<()> {
    let mut child = Command::new("node")
        .args([
            "--input-type=module",
            "--eval",
            include_str!("wasm_harness.mjs"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let input = child.stdin.take().unwrap();
    let output = BufReader::new(child.stdout.take().unwrap());
    let mut host = WasmHost(WebAssemblyBackend(Mutex::new(Bridge {
        child,
        input,
        output,
    })));
    host.start(|listener| {
        anyhow::ensure!(listener == 42, "listener capability");
        Ok(())
    })?;
    assert_eq!(host.secret("fixture")?.as_slice(), [17]);
    assert!(host.secret("not-authorized").is_err());
    assert_eq!(host.limits().memory_bytes, 32 * 1024 * 1024);
    let deadline = SystemTime::now() + Duration::from_millis(10);
    host.idle(Some(deadline)).await?;
    assert!(SystemTime::now() >= deadline);
    assert_eq!(
        host.listener()?,
        42,
        "same guest still accepts calls after idle"
    );
    host.restart(|_| Ok(()))?;
    host.stop()?;
    Ok(())
}
