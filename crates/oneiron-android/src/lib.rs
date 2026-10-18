//! Minimal JNI/Kotlin ownership adapter. The Java instance owns one engine vault,
//! or a share of the one its `EmbeddedEngine` serves (`engine`, behind the
//! `engine` feature).
//! No engine state lives in process-global native storage. A bound vault
//! (`EmbeddedVault.bound`) holds its own caller, its principal and session,
//! and writes as that caller (OF-063): its puts, deletes, edges and vectors
//! run the core's raw caller doors (`Memory::raw_*`). Every other vault
//! writes as the host. Reads are the same on every vault.
use jni::{
    JNIEnv,
    objects::{JByteArray, JFloatArray, JObject, JString, JValue},
    sys::{jboolean, jbyteArray, jfloat, jint, jlong, jobjectArray, jsize},
};
use oneiron::{
    EdgeActorClass, EdgeInfo, EdgeKind, EntityId, Memory, RawEntityPut, ScoredEntity, TimeRange,
    Vault, VaultConfig, parse_actor_key,
};
use std::sync::{Arc, MutexGuard};

/// The most hits one vector search answers, as the C ABI's
/// (`MAX_FFI_SEARCH_LIMIT`).
const MAX_SEARCH_LIMIT: usize = 1_000;

// Public so its JNI exports are reachable items, as this file's are.
#[cfg(feature = "engine")]
pub mod engine;

struct NativeVault {
    vault: Arc<Vault>,
    /// The caller a bound vault writes as; `None` writes as the host.
    binding: Option<Binding>,
}
/// The principal a bound vault's app host named, and the off-record
/// session, if any: this vault's alone, never process or engine state.
struct Binding {
    actor: EntityId,
    actor_class: EdgeActorClass,
    session: Option<String>,
}
impl NativeVault {
    /// A vault over `vault` that writes as the host.
    fn unbound(vault: Arc<Vault>) -> Self {
        Self {
            vault,
            binding: None,
        }
    }
    /// A NEW vault over this one's same open vault that writes as the caller
    /// `actor_key` names (core `parse_actor_key`), or the embedded owner when
    /// it is `None`, inside the off-record session `session` names, if any.
    fn bound(&self, actor_key: Option<&str>, session: Option<&str>) -> Result<Self, String> {
        let session = session.map(str::trim);
        if session.is_some_and(str::is_empty) {
            return Err("invalid off-record session reference".to_owned());
        }
        let (actor, actor_class) = match actor_key {
            Some(key) => parse_actor_key(&self.vault, key).map_err(display)?,
            None => (
                self.vault.ensure_embedded_owner_actor().map_err(display)?,
                EdgeActorClass::Human,
            ),
        };
        Ok(Self {
            vault: Arc::clone(&self.vault),
            binding: Some(Binding {
                actor,
                actor_class,
                session: session.map(str::to_owned),
            }),
        })
    }
    /// The bound caller's memory surface, its session bound.
    fn bound_memory(&self) -> Option<Memory<'_>> {
        self.binding.as_ref().map(|binding| {
            let memory = self.vault.memory(binding.actor, binding.actor_class);
            match binding.session.as_deref() {
                Some(session) => memory.in_off_record_session(session),
                None => memory,
            }
        })
    }
    fn open(path: &str) -> Result<Self, String> {
        // Crash output never carries world text: the engine's hook goes in before
        // any vault opens (owner ruling 2026-10-14, fix 6).
        oneiron::panic_report::install_panic_hook();
        Vault::open(path, VaultConfig::device())
            .map(|vault| Self::unbound(Arc::new(vault)))
            .map_err(display)
    }
    fn put(&self, id: &str, kind: jint, at: jlong, body: &[u8]) -> Result<(), String> {
        let id = EntityId::from_hex(id).map_err(display)?;
        let kind = u8::try_from(kind).map_err(display)?;
        let at = u64::try_from(at).map_err(display)?;
        let occurred = TimeRange { start: at, end: at };
        match self.bound_memory() {
            Some(memory) => memory
                .raw_put_entity(RawEntityPut {
                    id,
                    entity_type: kind,
                    occurred,
                    learned_at: at,
                    data: body,
                })
                .map_err(display),
            None => self
                .vault
                .put_entity(&id, kind, occurred, at, body)
                .map_err(display),
        }
    }
    fn get(&self, id: &str) -> Result<Option<Vec<u8>>, String> {
        self.vault
            .get(&EntityId::from_hex(id).map_err(display)?)
            .map_err(display)
    }
    /// Deletes `id`, answering whether a record was there. A bound vault
    /// deletes as its caller through the `vault.delete` door: owner-only,
    /// and an id naming no record is refused, with its refusal receipt.
    fn delete(&self, id: &str) -> Result<bool, String> {
        let id = EntityId::from_hex(id).map_err(display)?;
        match self.bound_memory() {
            Some(memory) => memory.raw_delete_entity(&id).map_err(display),
            None => self.vault.delete_entity(&id).map_err(display),
        }
    }
    /// Puts the edge `src` to `tgt` of the wire kind `kind`.
    fn put_edge(&self, src: &str, kind: jint, tgt: &str, weight: f32) -> Result<(), String> {
        let src = EntityId::from_hex(src).map_err(display)?;
        let tgt = EntityId::from_hex(tgt).map_err(display)?;
        let kind = u32::try_from(kind)
            .ok()
            .and_then(EdgeKind::from_wire)
            .ok_or_else(|| format!("unknown edge kind {kind}"))?;
        match self.bound_memory() {
            Some(memory) => memory
                .raw_put_edge(&src, kind, &tgt, weight)
                .map_err(display),
            None => self
                .vault
                .put_edge(&src, kind, &tgt, weight)
                .map_err(display),
        }
    }
    /// The edges out of `id`, or into it when `inbound`.
    fn edges(&self, id: &EntityId, inbound: bool) -> Result<Vec<EdgeInfo>, String> {
        let edges = if inbound {
            self.vault.edges_in(id)
        } else {
            self.vault.edges_out(id)
        };
        edges.map_err(display)
    }
    /// Puts `id`'s vector; the vault refuses one of another width.
    fn put_vector(&self, id: &str, vector: &[f32]) -> Result<(), String> {
        let id = EntityId::from_hex(id).map_err(display)?;
        match self.bound_memory() {
            Some(memory) => memory.raw_put_vector(&id, vector).map_err(display),
            None => self.vault.put_vector(&id, vector).map_err(display),
        }
    }
    /// The `limit` nearest entities to `query`, at most [`MAX_SEARCH_LIMIT`].
    fn search_vector(&self, query: &[f32], limit: jint) -> Result<Vec<ScoredEntity>, String> {
        let limit = usize::try_from(limit)
            .ok()
            .filter(|limit| *limit <= MAX_SEARCH_LIMIT)
            .ok_or_else(|| format!("search limit {limit} is not within 0..={MAX_SEARCH_LIMIT}"))?;
        self.vault.search_vector(query, limit).map_err(display)
    }
}
fn display(error: impl std::fmt::Display) -> String {
    error.to_string()
}
/// A Kotlin `FloatArray`'s values.
fn float_values(env: &JNIEnv<'_>, array: &JFloatArray<'_>) -> Result<Vec<f32>, String> {
    let len = env.get_array_length(array).map_err(display)?;
    let mut values = vec![0.0; usize::try_from(len).map_err(display)?];
    env.get_float_array_region(array, 0, &mut values)
        .map_err(display)?;
    Ok(values)
}
/// `edges` as a Kotlin `Array<VaultEdge>`. `own` is the id the read named:
/// each edge's source, or its target when `inbound`.
fn edge_array(
    env: &mut JNIEnv<'_>,
    own: &EntityId,
    inbound: bool,
    edges: Vec<EdgeInfo>,
) -> Result<jobjectArray, String> {
    let count = jsize::try_from(edges.len()).map_err(display)?;
    let array = env
        .new_object_array(count, "org/oneiron/VaultEdge", JObject::null())
        .map_err(display)?;
    for (index, edge) in (0..count).zip(edges) {
        let (src, tgt) = if inbound {
            (edge.target, *own)
        } else {
            (*own, edge.target)
        };
        let src = env.new_string(src.to_hex()).map_err(display)?;
        let tgt = env.new_string(tgt.to_hex()).map_err(display)?;
        let vad = match edge.vad {
            Some(vad) => {
                let values = env.new_float_array(3).map_err(display)?;
                env.set_float_array_region(&values, 0, &[vad.valence, vad.arousal, vad.dominance])
                    .map_err(display)?;
                JObject::from(values)
            }
            None => JObject::null(),
        };
        let created_at = jlong::try_from(edge.created_at).map_err(display)?;
        let element = env
            .new_object(
                "org/oneiron/VaultEdge",
                "(Ljava/lang/String;ILjava/lang/String;FJ[F)V",
                &[
                    (&src).into(),
                    JValue::Int(jint::from(edge.kind as u8)),
                    (&tgt).into(),
                    JValue::Float(edge.weight),
                    JValue::Long(created_at),
                    (&vad).into(),
                ],
            )
            .map_err(display)?;
        env.set_object_array_element(&array, index, &element)
            .map_err(display)?;
        env.delete_local_ref(src).map_err(display)?;
        env.delete_local_ref(tgt).map_err(display)?;
        env.delete_local_ref(vad).map_err(display)?;
        env.delete_local_ref(element).map_err(display)?;
    }
    Ok(array.into_raw())
}
/// `hits` as a Kotlin `Array<ScoredEntity>`, best first.
fn scored_array(env: &mut JNIEnv<'_>, hits: Vec<ScoredEntity>) -> Result<jobjectArray, String> {
    let count = jsize::try_from(hits.len()).map_err(display)?;
    let array = env
        .new_object_array(count, "org/oneiron/ScoredEntity", JObject::null())
        .map_err(display)?;
    for (index, hit) in (0..count).zip(hits) {
        let id = env.new_string(hit.id.to_hex()).map_err(display)?;
        let element = env
            .new_object(
                "org/oneiron/ScoredEntity",
                "(Ljava/lang/String;F)V",
                &[(&id).into(), JValue::Float(hit.score)],
            )
            .map_err(display)?;
        env.set_object_array_element(&array, index, &element)
            .map_err(display)?;
        env.delete_local_ref(id).map_err(display)?;
        env.delete_local_ref(element).map_err(display)?;
    }
    Ok(array.into_raw())
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
/// JNI implementation of the Kotlin `EmbeddedVault.bound`: a NEW vault over
/// `source`'s same open vault that writes as the caller its app host names.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EmbeddedVault_bindNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
    source: JObject<'_>,
    actor_key: JString<'_>,
    session: JString<'_>,
) {
    run(&mut env, |env| {
        let actor_key: Option<String> = if actor_key.is_null() {
            None
        } else {
            Some(env.get_string(&actor_key).map_err(display)?.into())
        };
        let session: Option<String> = if session.is_null() {
            None
        } else {
            Some(env.get_string(&session).map_err(display)?.into())
        };
        let vault = {
            // SAFETY: `source` is a live Kotlin `EmbeddedVault`, whose
            // synchronized instance alone owns this private field.
            let source: MutexGuard<'_, NativeVault> =
                unsafe { env.get_rust_field(&source, "nativeHandle") }.map_err(display)?;
            source.bound(actor_key.as_deref(), session.as_deref())?
        };
        // SAFETY: Kotlin owns the private long field, initialized to zero.
        // All native hooks execute under that instance's synchronized monitor.
        unsafe { env.set_rust_field(&object, "nativeHandle", vault) }.map_err(display)
    });
}
/// JNI implementation of the typed engine put door; no storage bypass. A
/// bound vault puts as its caller (OF-063).
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
        let bytes = {
            // SAFETY: same synchronized, private instance field as putNative.
            let vault: MutexGuard<'_, NativeVault> =
                unsafe { env.get_rust_field(&object, "nativeHandle") }.map_err(display)?;
            vault.get(&id)?
        };
        match bytes {
            Some(bytes) => env
                .byte_array_from_slice(&bytes)
                .map(JByteArray::into_raw)
                .map_err(display),
            None => Ok(std::ptr::null_mut()),
        }
    })
}
/// JNI delete; a bound vault deletes as its caller through the
/// `vault.delete` door (OF-063). Answers whether a record was there.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EmbeddedVault_deleteNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
    id: JString<'_>,
) -> jboolean {
    run(&mut env, |env| {
        let id: String = env.get_string(&id).map_err(display)?.into();
        // SAFETY: same synchronized, private instance field as putNative.
        let vault: MutexGuard<'_, NativeVault> =
            unsafe { env.get_rust_field(&object, "nativeHandle") }.map_err(display)?;
        vault.delete(&id).map(jboolean::from)
    })
}
/// JNI edge put; a bound vault puts it as its caller (OF-063).
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EmbeddedVault_putEdgeNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
    src: JString<'_>,
    kind: jint,
    target: JString<'_>,
    weight: jfloat,
) {
    run(&mut env, |env| {
        let src: String = env.get_string(&src).map_err(display)?.into();
        let target: String = env.get_string(&target).map_err(display)?.into();
        // SAFETY: same synchronized, private instance field as putNative.
        let vault: MutexGuard<'_, NativeVault> =
            unsafe { env.get_rust_field(&object, "nativeHandle") }.map_err(display)?;
        vault.put_edge(&src, kind, &target, weight)
    });
}
/// JNI edge read: the edges out of `id`, or into it when `inbound`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EmbeddedVault_edgesNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
    id: JString<'_>,
    inbound: jboolean,
) -> jobjectArray {
    run(&mut env, |env| {
        let id: String = env.get_string(&id).map_err(display)?.into();
        let own = EntityId::from_hex(&id).map_err(display)?;
        let inbound = inbound != 0;
        let edges = {
            // SAFETY: same synchronized, private instance field as putNative.
            let vault: MutexGuard<'_, NativeVault> =
                unsafe { env.get_rust_field(&object, "nativeHandle") }.map_err(display)?;
            vault.edges(&own, inbound)?
        };
        edge_array(env, &own, inbound, edges)
    })
}
/// JNI vector put; a bound vault puts it as its caller (OF-063).
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EmbeddedVault_putVectorNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
    id: JString<'_>,
    vector: JFloatArray<'_>,
) {
    run(&mut env, |env| {
        let id: String = env.get_string(&id).map_err(display)?.into();
        let vector = float_values(env, &vector)?;
        // SAFETY: same synchronized, private instance field as putNative.
        let vault: MutexGuard<'_, NativeVault> =
            unsafe { env.get_rust_field(&object, "nativeHandle") }.map_err(display)?;
        vault.put_vector(&id, &vector)
    });
}
/// JNI vector search: the `limit` nearest entities to `query`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EmbeddedVault_searchVectorNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
    query: JFloatArray<'_>,
    limit: jint,
) -> jobjectArray {
    run(&mut env, |env| {
        let query = float_values(env, &query)?;
        let hits = {
            // SAFETY: same synchronized, private instance field as putNative.
            let vault: MutexGuard<'_, NativeVault> =
                unsafe { env.get_rust_field(&object, "nativeHandle") }.map_err(display)?;
            vault.search_vector(&query, limit)?
        };
        scored_array(env, hits)
    })
}
/// JNI close drops this instance's vault: the vault itself, with its LMDB
/// environment, or its share of an engine's, which closes when the last
/// share and the engine have gone.
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
