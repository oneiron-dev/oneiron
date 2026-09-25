use super::*;
use crate::code_sandbox::microvm::{
    CredentialAllowlist, CredentialDestination, CredentialResolver,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct Resolver {
    calls: Mutex<Vec<String>>,
}
impl CredentialResolver for Resolver {
    fn resolve_for(
        &self,
        handle: &SandboxCredentialHandle,
        destination: &CredentialDestination,
    ) -> Result<Vec<u8>> {
        self.calls.lock().expect("test fixture").push(format!(
            "{}:{}",
            handle.as_str(),
            destination
        ));
        Ok(b"host-only-test-credential".to_vec())
    }
}
struct Transport {
    destinations: Mutex<Vec<String>>,
}
impl CredentialReadTransport for Transport {
    fn read(
        &self,
        destination: &CredentialDestination,
        operation: &crate::code_sandbox::SandboxCredentialOperation,
        _: &rmpv::Value,
        secret: &[u8],
    ) -> Result<()> {
        assert_eq!(secret, b"host-only-test-credential");
        assert_eq!(
            operation.effect(),
            crate::code_sandbox::SandboxCredentialEffect::ReadOnly
        );
        self.destinations
            .lock()
            .expect("test fixture")
            .push(destination.to_string());
        Ok(())
    }
}
fn send(stream: &mut UnixStream, frame: Value) {
    let bytes = frame.to_string().into_bytes();
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .expect("test fixture");
    stream.write_all(&bytes).expect("test fixture");
}
fn receive(stream: &mut UnixStream) -> Value {
    let mut size = [0; 4];
    stream.read_exact(&mut size).expect("test fixture");
    let mut bytes = vec![0; u32::from_be_bytes(size) as usize];
    stream.read_exact(&mut bytes).expect("test fixture");
    assert!(!String::from_utf8_lossy(&bytes).contains("host-only-test-credential"));
    serde_json::from_slice(&bytes).expect("test fixture")
}

#[test]
fn socket_protocol_denies_off_list_before_resolution_and_returns_proposals_not_writes() -> Result<()>
{
    let dir = tempfile::tempdir().expect("test fixture");
    let base = dir.path().join("base");
    std::fs::create_dir(&base).expect("test fixture");
    std::fs::write(base.join("input.txt"), b"base").expect("test fixture");
    let vm = MicroVmHandle::new(
        "protocol-test",
        crate::code_sandbox::SandboxGuestTier::Foreign,
        &base,
        dir.path().join("upper"),
        dir.path().join("egress.sock"),
    )?;
    let resolver = Arc::new(Resolver {
        calls: Mutex::new(vec![]),
    });
    let mut allow = CredentialAllowlist::new();
    allow.allow(
        &SandboxCredentialHandle::new("handle")?,
        CredentialDestination::new("https", "example.com")?,
    );
    let mut proxy = CredentialEgressProxy::new(allow, resolver.clone());
    proxy.arm();
    let transport = Transport {
        destinations: Mutex::new(vec![]),
    };
    let (host, mut guest) = UnixStream::pair().expect("test fixture");
    guest
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("test fixture");
    let result = std::thread::scope(|scope| {
        scope.spawn(move || {
            send(&mut guest,json!({"type":"hello","version":1}));
            let start = receive(&mut guest);
            assert_eq!(start["type"], "start");
            assert_eq!(start["source"], "fixture source");
            loop { if receive(&mut guest)["type"]=="ready" {break;} }
            send(&mut guest,json!({"type":"credential_read","handle":"handle","operation":"metadata","scheme":"https","host":"evil.test"}));
            assert_eq!(receive(&mut guest),json!({"type":"receipt","accepted":false}));
            send(&mut guest,json!({"type":"credential_read","handle":"handle","operation":"metadata","scheme":"https","host":"api.example.com"}));
            assert_eq!(receive(&mut guest),json!({"type":"receipt","accepted":true}));
            send(&mut guest,json!({"type":"write","path":"/mnt/workspace/result.txt","bytes":[111,107]}));
            assert_eq!(receive(&mut guest),json!({"type":"receipt","accepted":true}));
            send(&mut guest,json!({"type":"finish","status":0}));
        });
        exchange(
            host,
            &vm,
            GuestProgram {
                component: b"bounded-component-input",
                source: "fixture source",
            },
            ExecutionBudget::new(3, 128, 32),
            Instant::now() + Duration::from_secs(3),
            &proxy,
            Some(&transport),
        )
    })?;
    assert_eq!(
        resolver.calls.lock().expect("test fixture").as_slice(),
        &["handle:https://api.example.com"]
    );
    assert_eq!(
        transport
            .destinations
            .lock()
            .expect("test fixture")
            .as_slice(),
        &["https://api.example.com"]
    );
    assert!(result.0.overlay_dirty);
    let [SandboxProposalWrite::FileEdit(file)] = result.1.as_slice() else {
        panic!("one file proposal")
    };
    assert_eq!(file.path.as_str(), "/mnt/workspace/result.txt");
    assert_eq!(file.edit.replacement, "ok");
    assert_eq!(file.edit.start, 0);
    assert_eq!(file.edit.end, 0);
    assert_eq!(
        std::fs::read(base.join("input.txt")).expect("test fixture"),
        b"base"
    );
    assert!(!base.join("result.txt").exists());
    Ok(())
}

#[test]
fn oversized_frame_and_expired_deadline_fail_closed() {
    let (mut host, mut guest) = UnixStream::pair().expect("test fixture");
    guest
        .write_all(&((MAX_FRAME + 1) as u32).to_be_bytes())
        .expect("test fixture");
    assert!(read_frame(&mut host, Instant::now() + Duration::from_secs(1)).is_err());
    assert!(read_frame(&mut host, Instant::now()).is_err());
}
