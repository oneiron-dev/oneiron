//! Minimal JNI/Kotlin ownership adapter. The Java instance owns one engine vault.
//! No engine state lives in process-global native storage.
use jni::{
    JNIEnv,
    objects::{JByteArray, JObject, JString},
    sys::{jbyteArray, jint, jlong},
};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use std::sync::MutexGuard;

struct NativeVault {
    vault: Vault,
}
impl NativeVault {
    fn open(path: &str) -> Result<Self, String> {
        Vault::open(path, VaultConfig::device())
            .map(|vault| Self { vault })
            .map_err(display)
    }
    fn put(&self, id: &str, kind: jint, at: jlong, body: &[u8]) -> Result<(), String> {
        let id = EntityId::from_hex(id).map_err(display)?;
        let kind = u8::try_from(kind).map_err(display)?;
        let at = u64::try_from(at).map_err(display)?;
        self.vault
            .put_entity(&id, kind, TimeRange { start: at, end: at }, at, body)
            .map_err(display)
    }
    fn get(&self, id: &str) -> Result<Option<Vec<u8>>, String> {
        self.vault
            .get(&EntityId::from_hex(id).map_err(display)?)
            .map_err(display)
    }
}
fn display(error: impl std::fmt::Display) -> String {
    error.to_string()
}
fn run<T: Default>(
    env: &mut JNIEnv<'_>,
    call: impl FnOnce(&mut JNIEnv<'_>) -> Result<T, String>,
) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| call(env))) {
        Ok(Ok(value)) => value,
        Ok(Err(message)) => {
            let _ = env.throw_new("java/lang/IllegalStateException", message);
            T::default()
        }
        Err(_) => {
            let _ = env.throw_new("java/lang/IllegalStateException", "native engine panic");
            T::default()
        }
    }
}

/// JNI implementation of the private Kotlin constructor hook.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EmbeddedVault_openNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
    path: JString<'_>,
) {
    run(&mut env, |env| {
        let path: String = env.get_string(&path).map_err(display)?.into();
        let vault = NativeVault::open(&path)?;
        // SAFETY: Kotlin owns the private long field, initialized to zero.
        // All native hooks execute under that instance's synchronized monitor.
        unsafe { env.set_rust_field(&object, "nativeHandle", vault) }.map_err(display)
    });
}
/// JNI implementation of the typed engine put door; no storage bypass.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EmbeddedVault_putNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
    id: JString<'_>,
    kind: jint,
    at: jlong,
    body: JByteArray<'_>,
) {
    run(&mut env, |env| {
        let id: String = env.get_string(&id).map_err(display)?.into();
        let bytes = env.convert_byte_array(&body).map_err(display)?;
        // SAFETY: the synchronized Kotlin instance alone owns this private
        // field; close takes it once and clears it before any later access.
        let vault: MutexGuard<'_, NativeVault> =
            unsafe { env.get_rust_field(&object, "nativeHandle") }.map_err(display)?;
        vault.put(&id, kind, at, &bytes)
    });
}
/// JNI read returns null only for an absent row; failures throw.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EmbeddedVault_getNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
    id: JString<'_>,
) -> jbyteArray {
    run(&mut env, |env| {
        let id: String = env.get_string(&id).map_err(display)?.into();
        // SAFETY: same synchronized, private instance field as putNative.
        let bytes = {
            let vault: MutexGuard<'_, NativeVault> =
                unsafe { env.get_rust_field(&object, "nativeHandle") }.map_err(display)?;
            vault.get(&id)?
        };
        match bytes {
            Some(bytes) => env
                .byte_array_from_slice(&bytes)
                .map(|array| array.into_raw())
                .map_err(display),
            None => Ok(std::ptr::null_mut()),
        }
    })
}
/// JNI close drops the actual Rust vault, including its LMDB environment.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EmbeddedVault_closeNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
) {
    run(&mut env, |env| {
        // SAFETY: synchronized close owns the field exclusively and runs once;
        // take_rust_field clears it so subsequent native reads fail closed.
        let vault: NativeVault =
            unsafe { env.take_rust_field(&object, "nativeHandle") }.map_err(display)?;
        drop(vault);
        Ok(())
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn same_core_round_trip_and_invalid_id_refusal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().to_str().expect("UTF-8 path");
        let id = "0102030405060708090a0b0c0d0e0f10";
        let vault = NativeVault::open(path).expect("open");
        vault.put(id, 4, 1, b"android round trip").expect("put");
        assert_eq!(
            vault.get(id).expect("get"),
            Some(b"android round trip".to_vec())
        );
        assert!(vault.put("not-an-id", 4, 1, b"bad").is_err());
        drop(vault);
        assert_eq!(
            NativeVault::open(path)
                .expect("reopen")
                .get(id)
                .expect("get"),
            Some(b"android round trip".to_vec())
        );
    }
}
