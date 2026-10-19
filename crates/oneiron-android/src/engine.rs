//! The embedded engine (OF-237) behind the Kotlin `EmbeddedEngine`: the full
//! server `oneiron serve` runs, in the app's process, over the vault at one
//! path. The plain `EmbeddedVault(path)` stays beside it, a vault with no
//! server.
//!
//! The Kotlin object's field holds one `Arc` of the engine. Each call clones
//! it out and releases the field before it blocks, so no lock and no Kotlin
//! monitor is held while the engine calls back into the app's `AppHost`. A
//! Kotlin `EngineConnection` holds its connection the same way, with a share
//! of the engine it belongs to; one on the artifact app's own origin (`/a/`)
//! is an `EngineConnection` too.
//!
//! An engine failure throws `org.oneiron.EngineException`, an
//! `IllegalStateException` carrying its cause's stable code; every other
//! failure throws a plain `IllegalStateException`, as the vault's do.

use std::path::Path;
use std::sync::{Arc, MutexGuard};
use std::time::SystemTime;

use jni::objects::{GlobalRef, JByteArray, JObject, JObjectArray, JString, JThrowable, JValue};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jobject, jsize};
use jni::{JNIEnv, JavaVM};
use oneiron_server::embedded::{
    BlockingConnection, BlockingEngine, EmbeddedReply, EmbeddedRequest, embedded_serve_config,
    engine_error_kind, host_limits, unix_millis,
};
use oneiron_vault_contract::host_adapters::AppHost;
use zeroize::Zeroizing;

use super::NativeVault;

/// What a Kotlin `EmbeddedEngine`'s field holds.
type NativeEngine = Arc<BlockingEngine<JniAppHost>>;

/// One connection the app holds, and the engine it belongs to, kept until
/// the connection goes.
struct HeldConnection {
    connection: BlockingConnection,
    _engine: NativeEngine,
}

/// What a Kotlin `EngineConnection`'s field holds.
type NativeConnection = Arc<HeldConnection>;

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

/// What a JNI engine call throws.
enum Thrown {
    /// An engine failure: an `EngineException` with its cause's stable code.
    Engine { code: &'static str, message: String },
    /// Any other failure: an `IllegalStateException`.
    Other(String),
}

/// An engine failure, by the cause the engine named, never its words.
fn chain(error: anyhow::Error) -> Thrown {
    Thrown::Engine {
        code: engine_error_kind(&error).code(),
        message: format!("{error:#}"),
    }
}

fn other(error: impl std::fmt::Display) -> Thrown {
    Thrown::Other(error.to_string())
}

/// `super::run` for an engine call: an engine failure throws an
/// `EngineException`.
fn run_engine<T: Default>(
    env: &mut JNIEnv<'_>,
    call: impl FnOnce(&mut JNIEnv<'_>) -> Result<T, Thrown>,
) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| call(env))) {
        Ok(Ok(value)) => value,
        Ok(Err(Thrown::Engine { code, message })) => {
            throw_engine(env, code, &message);
            T::default()
        }
        Ok(Err(Thrown::Other(message))) => {
            let _ = env.throw_new("java/lang/IllegalStateException", message);
            T::default()
        }
        Err(_) => {
            let _ = env.throw_new("java/lang/IllegalStateException", "native engine panic");
            T::default()
        }
    }
}

/// Throws `org.oneiron.EngineException(code, message)`, or, when it cannot
/// be built, the `IllegalStateException` the message alone is.
fn throw_engine(env: &mut JNIEnv<'_>, code: &str, message: &str) {
    let thrown = (|| -> jni::errors::Result<()> {
        let code = env.new_string(code)?;
        let text = env.new_string(message)?;
        let exception = env.new_object(
            "org/oneiron/EngineException",
            "(Ljava/lang/String;Ljava/lang/String;)V",
            &[(&code).into(), (&text).into()],
        )?;
        env.throw(JThrowable::from(exception))
    })();
    if thrown.is_err() {
        let _ = env.exception_clear();
        let _ = env.throw_new("java/lang/IllegalStateException", message);
    }
}

/// The engine `object` owns, cloned out of its field, whose lock is released
/// before this returns.
fn engine_of(env: &mut JNIEnv<'_>, object: &JObject<'_>) -> Result<NativeEngine, Thrown> {
    // SAFETY: the Kotlin `EmbeddedEngine` alone owns this private field:
    // startNative sets it once and closeNative takes it once.
    let engine: MutexGuard<'_, NativeEngine> =
        unsafe { env.get_rust_field(object, "nativeHandle") }.map_err(other)?;
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
    run_engine(&mut env, |env| {
        let path: String = env.get_string(&path).map_err(other)?.into();
        let config_file: Option<String> = if config_file.is_null() {
            None
        } else {
            Some(env.get_string(&config_file).map_err(other)?.into())
        };
        let dimensions = usize::try_from(dimensions).map_err(other)?;
        let limits = host_limits(
            u64::try_from(memory_bytes).ok().filter(|&bytes| bytes > 0),
            u32::try_from(cpu_millis_per_second)
                .ok()
                .filter(|&millis| millis > 0),
        );
        let host = JniAppHost(Arc::new(JavaHost {
            vm: env.get_java_vm().map_err(other)?,
            host: env.new_global_ref(&host).map_err(other)?,
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
        unsafe { env.set_rust_field(&object, "nativeHandle", engine) }.map_err(other)
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
    run_engine(&mut env, |env| {
        let request = EmbeddedRequest {
            method: env.get_string(&method).map_err(other)?.into(),
            path: env.get_string(&path).map_err(other)?.into(),
            headers: request_headers(env, &header_names, &header_values)?,
            body: env.convert_byte_array(&body).map_err(other)?,
        };
        let reply = engine_of(env, &object)?.request(request).map_err(chain)?;
        reply_object(env, reply)
    })
}

/// JNI implementation of the buffered request on the artifact app's own
/// origin (`/a/`).
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EmbeddedEngine_artifactRequestNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
    method: JString<'_>,
    path: JString<'_>,
    header_names: JObjectArray<'_>,
    header_values: JObjectArray<'_>,
    body: JByteArray<'_>,
) -> jobject {
    run_engine(&mut env, |env| {
        let request = EmbeddedRequest {
            method: env.get_string(&method).map_err(other)?.into(),
            path: env.get_string(&path).map_err(other)?.into(),
            headers: request_headers(env, &header_names, &header_values)?,
            body: env.convert_byte_array(&body).map_err(other)?,
        };
        let reply = engine_of(env, &object)?
            .request_artifact(request)
            .map_err(chain)?;
        reply_object(env, reply)
    })
}

/// The request's headers, one name to one value.
fn request_headers(
    env: &mut JNIEnv<'_>,
    names: &JObjectArray<'_>,
    values: &JObjectArray<'_>,
) -> Result<Vec<(String, Vec<u8>)>, Thrown> {
    let count = env.get_array_length(names).map_err(other)?;
    if count != env.get_array_length(values).map_err(other)? {
        return Err(Thrown::Other("each header name takes one value".to_owned()));
    }
    let mut headers = Vec::new();
    for index in 0..count {
        let name = JString::from(env.get_object_array_element(names, index).map_err(other)?);
        let value = JByteArray::from(env.get_object_array_element(values, index).map_err(other)?);
        let header: (String, Vec<u8>) = (
            env.get_string(&name).map_err(other)?.into(),
            env.convert_byte_array(&value).map_err(other)?,
        );
        env.delete_local_ref(name).map_err(other)?;
        env.delete_local_ref(value).map_err(other)?;
        headers.push(header);
    }
    Ok(headers)
}

/// The reply as a Kotlin `EngineReply`.
fn reply_object(env: &mut JNIEnv<'_>, reply: EmbeddedReply) -> Result<jobject, Thrown> {
    let count = jsize::try_from(reply.headers.len()).map_err(other)?;
    let names = env
        .new_object_array(count, "java/lang/String", JObject::null())
        .map_err(other)?;
    let values = env
        .new_object_array(count, "[B", JObject::null())
        .map_err(other)?;
    for (index, (name, value)) in (0..count).zip(&reply.headers) {
        let name = env.new_string(name).map_err(other)?;
        let value = env.byte_array_from_slice(value).map_err(other)?;
        env.set_object_array_element(&names, index, &name)
            .map_err(other)?;
        env.set_object_array_element(&values, index, &value)
            .map_err(other)?;
        env.delete_local_ref(name).map_err(other)?;
        env.delete_local_ref(value).map_err(other)?;
    }
    let body = env.byte_array_from_slice(&reply.body).map_err(other)?;
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
    .map_err(other)
}

/// JNI implementation of the engine wake.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EmbeddedEngine_wakeNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
) {
    run_engine(&mut env, |env| {
        engine_of(env, &object)?.wake().map_err(chain)
    });
}

/// JNI implementation of the engine stop.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EmbeddedEngine_stopNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
) {
    run_engine(&mut env, |env| {
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
    run_engine(&mut env, |env| {
        // SAFETY: Kotlin's close runs this once; take_rust_field clears the
        // field, so later native calls fail closed.
        let engine: NativeEngine =
            unsafe { env.take_rust_field(&object, "nativeHandle") }.map_err(other)?;
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
    run_engine(&mut env, |env| {
        let vault = NativeVault::unbound(engine_of(env, &engine)?.vault().map_err(chain)?);
        // SAFETY: Kotlin owns the private long field, initialized to zero.
        // All native hooks execute under that instance's synchronized monitor.
        unsafe { env.set_rust_field(&object, "nativeHandle", vault) }.map_err(other)
    });
}

/// The connection `object` owns, cloned out of its field, whose lock is
/// released before this returns.
fn connection_of(env: &mut JNIEnv<'_>, object: &JObject<'_>) -> Result<NativeConnection, Thrown> {
    // SAFETY: the Kotlin `EngineConnection` alone owns this private field:
    // openNative sets it once and closeNative takes it once.
    let connection: MutexGuard<'_, NativeConnection> =
        unsafe { env.get_rust_field(object, "nativeHandle") }.map_err(other)?;
    Ok(Arc::clone(&connection))
}

/// JNI implementation of the Kotlin `EngineConnection` constructor over an
/// engine: one fresh connection to its server, on the artifact app's own
/// origin (`/a/`) when `artifacts`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EngineConnection_openNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
    engine: JObject<'_>,
    artifacts: jboolean,
) {
    run_engine(&mut env, |env| {
        let engine = engine_of(env, &engine)?;
        let connection = if artifacts != 0 {
            engine.connect_artifact()
        } else {
            engine.connect()
        };
        let connection: NativeConnection = Arc::new(HeldConnection {
            connection: connection.map_err(chain)?,
            _engine: engine,
        });
        // SAFETY: Kotlin owns the private long field, zero until this sets it
        // once, before the constructor returns.
        unsafe { env.set_rust_field(&object, "nativeHandle", connection) }.map_err(other)
    });
}

/// JNI implementation of the connection send.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EngineConnection_sendNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
    bytes: JByteArray<'_>,
) {
    run_engine(&mut env, |env| {
        let bytes = env.convert_byte_array(&bytes).map_err(other)?;
        connection_of(env, &object)?
            .connection
            .send(&bytes)
            .map_err(chain)
    });
}

/// JNI implementation of the connection receive: the next bytes, empty once
/// the connection has ended.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EngineConnection_receiveNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
) -> jbyteArray {
    run_engine(&mut env, |env| {
        let bytes = connection_of(env, &object)?
            .connection
            .receive()
            .map_err(chain)?;
        env.byte_array_from_slice(&bytes)
            .map(JByteArray::into_raw)
            .map_err(other)
    })
}

/// JNI close ends the app's side of the connection and releases this
/// object's share of it; a receive blocked on another thread returns empty.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EngineConnection_closeNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
) {
    run_engine(&mut env, |env| {
        // SAFETY: Kotlin's close runs this once; take_rust_field clears the
        // field, so later native calls fail closed.
        let connection: NativeConnection =
            unsafe { env.take_rust_field(&object, "nativeHandle") }.map_err(other)?;
        connection.connection.close().map_err(chain)
    });
}
