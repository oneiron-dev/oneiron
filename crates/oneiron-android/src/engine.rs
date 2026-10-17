//! The embedded engine (OF-237) behind the Kotlin `EmbeddedEngine`: the full
//! server `oneiron serve` runs, in the app's process, over the vault at one
//! path. The plain `EmbeddedVault(path)` stays beside it, a vault with no
//! server.
//!
//! The Kotlin object's field holds one `Arc` of the engine. Each call clones
//! it out and releases the field before it blocks, so no lock and no Kotlin
//! monitor is held while the engine calls back into the app's `AppHost`.

use std::path::Path;
use std::sync::{Arc, MutexGuard};
use std::time::SystemTime;

use jni::objects::{GlobalRef, JByteArray, JObject, JObjectArray, JString, JValue};
use jni::sys::{jint, jlong, jobject, jsize};
use jni::{JNIEnv, JavaVM};
use oneiron_server::embedded::{
    BlockingEngine, EmbeddedReply, EmbeddedRequest, embedded_serve_config, host_limits, unix_millis,
};
use oneiron_vault_contract::host_adapters::AppHost;
use zeroize::Zeroizing;

use super::{NativeVault, display, run};

/// What a Kotlin `EmbeddedEngine`'s field holds.
type NativeEngine = Arc<BlockingEngine<JniAppHost>>;

/// The Kotlin `AppHost` and the JVM to call it on.
struct JavaHost {
    vm: JavaVM,
    host: GlobalRef,
}

/// The Kotlin `AppHost` as the engine's host.
#[derive(Clone)]
struct JniAppHost(Arc<JavaHost>);

impl JniAppHost {
    /// One call into the Kotlin host, with the calling thread attached for
    /// the call. A Java exception it throws is cleared and becomes the
    /// error.
    fn call<T>(
        &self,
        call: impl FnOnce(&mut JNIEnv<'_>, &JObject<'_>) -> jni::errors::Result<T>,
    ) -> anyhow::Result<T> {
        let mut env = self.0.vm.attach_current_thread().map_err(|error| {
            anyhow::anyhow!("the app host's thread did not attach to the JVM: {error}")
        })?;
        let called = call(&mut *env, self.0.host.as_obj());
        if env.exception_check().unwrap_or(true) {
            let _ = env.exception_clear();
            anyhow::bail!("the app host threw");
        }
        called.map_err(|error| anyhow::anyhow!("the app host call failed: {error}"))
    }
}

impl AppHost for JniAppHost {
    fn keychain(&mut self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let secret = self.call(|env, host| {
            let java_name = env.new_string(name)?;
            let value = env
                .call_method(
                    host,
                    "keychain",
                    "(Ljava/lang/String;)[B",
                    &[(&java_name).into()],
                )?
                .l()?;
            if value.is_null() {
                return Ok(None);
            }
            env.convert_byte_array(&JByteArray::from(value))
                .map(|bytes| Some(Zeroizing::new(bytes)))
        })?;
        secret.ok_or_else(|| anyhow::anyhow!("no such secret in the app keychain: {name}"))
    }

    fn schedule_wake(&mut self, at: Option<SystemTime>) -> anyhow::Result<()> {
        let at_unix_ms = at.map(|at| i64::try_from(unix_millis(at)).unwrap_or(i64::MAX));
        self.call(|env, host| {
            let at = match at_unix_ms {
                Some(ms) => env
                    .call_static_method(
                        "java/lang/Long",
                        "valueOf",
                        "(J)Ljava/lang/Long;",
                        &[JValue::Long(ms)],
                    )?
                    .l()?,
                None => JObject::null(),
            };
            env.call_method(host, "scheduleWake", "(Ljava/lang/Long;)V", &[(&at).into()])?
                .v()
        })
    }

    fn ready(&mut self) -> anyhow::Result<()> {
        self.call(|env, host| env.call_method(host, "ready", "()V", &[])?.v())
    }
}

fn chain(error: anyhow::Error) -> String {
    format!("{error:#}")
}

/// The engine `object` owns, cloned out of its field, whose lock is released
/// before this returns.
fn engine_of(env: &mut JNIEnv<'_>, object: &JObject<'_>) -> Result<NativeEngine, String> {
    // SAFETY: the Kotlin `EmbeddedEngine` alone owns this private field:
    // startNative sets it once and closeNative takes it once.
    let engine: MutexGuard<'_, NativeEngine> =
        unsafe { env.get_rust_field(object, "nativeHandle") }.map_err(display)?;
    Ok(Arc::clone(&engine))
}

/// JNI implementation of the Kotlin `EmbeddedEngine` constructor hook.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EmbeddedEngine_startNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
    path: JString<'_>,
    host: JObject<'_>,
    config_file: JString<'_>,
    dimensions: jint,
    memory_bytes: jlong,
    cpu_millis_per_second: jint,
) {
    run(&mut env, |env| {
        let path: String = env.get_string(&path).map_err(display)?.into();
        let config_file: Option<String> = if config_file.is_null() {
            None
        } else {
            Some(env.get_string(&config_file).map_err(display)?.into())
        };
        let dimensions = usize::try_from(dimensions).map_err(display)?;
        let limits = host_limits(
            u64::try_from(memory_bytes).ok().filter(|&bytes| bytes > 0),
            u32::try_from(cpu_millis_per_second)
                .ok()
                .filter(|&millis| millis > 0),
        );
        let host = JniAppHost(Arc::new(JavaHost {
            vm: env.get_java_vm().map_err(display)?,
            host: env.new_global_ref(&host).map_err(display)?,
        }));
        // Crash output never carries world text: the engine's hook goes in
        // before any vault opens (owner ruling 2026-10-14, fix 6).
        oneiron::panic_report::install_panic_hook();
        let config = embedded_serve_config(
            Path::new(&path),
            (dimensions != 0).then_some(dimensions),
            config_file.as_deref().map(Path::new),
        )
        .map_err(chain)?;
        let engine: NativeEngine =
            Arc::new(BlockingEngine::start(host, config, limits).map_err(chain)?);
        // SAFETY: Kotlin owns the private long field, zero until this sets it
        // once, before the constructor returns.
        unsafe { env.set_rust_field(&object, "nativeHandle", engine) }.map_err(display)
    });
}

/// JNI implementation of the buffered engine request.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EmbeddedEngine_requestNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
    method: JString<'_>,
    path: JString<'_>,
    header_names: JObjectArray<'_>,
    header_values: JObjectArray<'_>,
    body: JByteArray<'_>,
) -> jobject {
    run(&mut env, |env| {
        let request = EmbeddedRequest {
            method: env.get_string(&method).map_err(display)?.into(),
            path: env.get_string(&path).map_err(display)?.into(),
            headers: request_headers(env, &header_names, &header_values)?,
            body: env.convert_byte_array(&body).map_err(display)?,
        };
        let reply = engine_of(env, &object)?.request(request).map_err(chain)?;
        reply_object(env, reply)
    })
}

/// The request's headers, one name to one value.
fn request_headers(
    env: &mut JNIEnv<'_>,
    names: &JObjectArray<'_>,
    values: &JObjectArray<'_>,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    let count = env.get_array_length(names).map_err(display)?;
    if count != env.get_array_length(values).map_err(display)? {
        return Err("each header name takes one value".to_owned());
    }
    let mut headers = Vec::new();
    for index in 0..count {
        let name = JString::from(
            env.get_object_array_element(names, index)
                .map_err(display)?,
        );
        let value = JByteArray::from(
            env.get_object_array_element(values, index)
                .map_err(display)?,
        );
        let header: (String, Vec<u8>) = (
            env.get_string(&name).map_err(display)?.into(),
            env.convert_byte_array(&value).map_err(display)?,
        );
        env.delete_local_ref(name).map_err(display)?;
        env.delete_local_ref(value).map_err(display)?;
        headers.push(header);
    }
    Ok(headers)
}

/// The reply as a Kotlin `EngineReply`.
fn reply_object(env: &mut JNIEnv<'_>, reply: EmbeddedReply) -> Result<jobject, String> {
    let count = jsize::try_from(reply.headers.len()).map_err(display)?;
    let names = env
        .new_object_array(count, "java/lang/String", JObject::null())
        .map_err(display)?;
    let values = env
        .new_object_array(count, "[B", JObject::null())
        .map_err(display)?;
    for (index, (name, value)) in (0..count).zip(&reply.headers) {
        let name = env.new_string(name).map_err(display)?;
        let value = env.byte_array_from_slice(value).map_err(display)?;
        env.set_object_array_element(&names, index, &name)
            .map_err(display)?;
        env.set_object_array_element(&values, index, &value)
            .map_err(display)?;
        env.delete_local_ref(name).map_err(display)?;
        env.delete_local_ref(value).map_err(display)?;
    }
    let body = env.byte_array_from_slice(&reply.body).map_err(display)?;
    env.new_object(
        "org/oneiron/EngineReply",
        "(I[Ljava/lang/String;[[B[B)V",
        &[
            JValue::Int(i32::from(reply.status)),
            (&names).into(),
            (&values).into(),
            (&body).into(),
        ],
    )
    .map(JObject::into_raw)
    .map_err(display)
}

/// JNI implementation of the engine wake.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EmbeddedEngine_wakeNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
) {
    run(&mut env, |env| {
        engine_of(env, &object)?.wake().map_err(chain)
    });
}

/// JNI implementation of the engine stop.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EmbeddedEngine_stopNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
) {
    run(&mut env, |env| {
        engine_of(env, &object)?.stop().map_err(chain)
    });
}

/// JNI close stops the engine in order and releases its runtime. Vaults
/// shared from it keep the vault until each closes.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EmbeddedEngine_closeNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
) {
    run(&mut env, |env| {
        // SAFETY: Kotlin's close runs this once; take_rust_field clears the
        // field, so later native calls fail closed.
        let engine: NativeEngine =
            unsafe { env.take_rust_field(&object, "nativeHandle") }.map_err(display)?;
        engine.close().map_err(chain)
    });
}

/// JNI implementation of the Kotlin `EmbeddedVault` constructor over an
/// engine's vault: the same open vault, never opened again.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EmbeddedVault_shareNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
    engine: JObject<'_>,
) {
    run(&mut env, |env| {
        let vault = NativeVault {
            vault: engine_of(env, &engine)?.vault().map_err(chain)?,
        };
        // SAFETY: Kotlin owns the private long field, initialized to zero.
        // All native hooks execute under that instance's synchronized monitor.
        unsafe { env.set_rust_field(&object, "nativeHandle", vault) }.map_err(display)
    });
}
