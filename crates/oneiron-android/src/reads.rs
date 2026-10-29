//! The Kotlin `EmbeddedVault`'s context pack, text search and graph reads,
//! lowered to the same core reads the C ABI's `oneiron_vault_context_pack`,
//! `_search_text`, `_targets`, `_sources`, `_subtree` and `_ancestors` run.
//! Reads are the same on every vault, bound or not, except `peers`, which
//! reads a session-bound vault's room over base (FIX 11586).

use std::sync::MutexGuard;

use jni::JNIEnv;
use jni::objects::{JFloatArray, JObject, JString, JValue};
use jni::sys::{jboolean, jint, jobjectArray, jsize, jstring};
use oneiron::{EdgeKind, EntityId, PackFormat, ScoredEntity};

use super::{NativeVault, display, float_values, run, scored_array};

impl NativeVault {
    /// A context pack over `text` and `vector`, at most `limit` items, as
    /// UTF-8 in `format`.
    fn context_pack(
        &self,
        text: Option<&str>,
        vector: Option<&[f32]>,
        limit: jint,
        format: Option<&str>,
    ) -> Result<String, String> {
        let limit = search_limit(limit)?;
        // The limit caps the pack itself, as the C ABI's does.
        let mut builder = self
            .vault
            .context_pack()
            .format(pack_format(format))
            .limit(limit);
        if let Some(text) = text {
            builder = builder.search_text(text, limit);
        }
        if let Some(vector) = vector {
            builder = builder.search_vector(vector, limit);
        }
        let pack = builder.run_serialized().map_err(display)?;
        String::from_utf8(pack).map_err(display)
    }

    /// The `limit` best BM25 text matches for `query`.
    fn search_text(&self, query: &str, limit: jint) -> Result<Vec<ScoredEntity>, String> {
        let limit = search_limit(limit)?;
        self.vault.search_text(query, limit).map_err(display)
    }

    /// The peers of `id` over `kind` edges, filtered to `peer_type` when
    /// given: its targets, or its sources when `inbound`.
    fn peers(
        &self,
        id: &str,
        kind: jint,
        peer_type: Option<jint>,
        inbound: bool,
    ) -> Result<Vec<EntityId>, String> {
        let id = EntityId::from_hex(id).map_err(display)?;
        let kind = u32::try_from(kind)
            .ok()
            .and_then(EdgeKind::from_wire)
            .ok_or_else(|| format!("unknown edge kind {kind}"))?;
        let peer_type = peer_type
            .map(|peer_type| u8::try_from(peer_type).map_err(display))
            .transpose()?;
        match (self.session_memory(), inbound) {
            (Some(memory), true) => memory.raw_sources(&id, kind, peer_type).map_err(display),
            (Some(memory), false) => memory.raw_targets(&id, kind, peer_type).map_err(display),
            (None, true) => self.vault.sources(&id, kind, peer_type).map_err(display),
            (None, false) => self.vault.targets(&id, kind, peer_type).map_err(display),
        }
    }

    /// The `ChildOf` descendants of `root` to `max_depth`, each with its depth.
    fn subtree(&self, root: &str, max_depth: jint) -> Result<Vec<(EntityId, u32)>, String> {
        let root = EntityId::from_hex(root).map_err(display)?;
        let max_depth = u32::try_from(max_depth).map_err(display)?;
        self.vault.subtree(&root, max_depth).map_err(display)
    }

    /// The `ChildOf` ancestors of `node`, nearest first.
    fn ancestors(&self, node: &str) -> Result<Vec<EntityId>, String> {
        let node = EntityId::from_hex(node).map_err(display)?;
        self.vault.ancestors(&node).map_err(display)
    }
}

/// A search limit as the engine's row count: any `jint` from zero up, served
/// whole; a negative one names no count.
pub(super) fn search_limit(limit: jint) -> Result<usize, String> {
    usize::try_from(limit).map_err(|_| format!("search limit {limit} is negative"))
}

/// The pack format `format` names, JSON when it names none, as the C ABI
/// reads it.
fn pack_format(format: Option<&str>) -> PackFormat {
    match format {
        Some("yaml") => PackFormat::Yaml,
        Some("toon") => PackFormat::Toon,
        Some("markdown") => PackFormat::Markdown,
        Some("plaintext") => PackFormat::Plaintext,
        _ => PackFormat::Json,
    }
}

/// A nullable Kotlin `String`.
fn optional_string(env: &mut JNIEnv<'_>, text: &JString<'_>) -> Result<Option<String>, String> {
    if text.is_null() {
        return Ok(None);
    }
    Ok(Some(env.get_string(text).map_err(display)?.into()))
}

/// `ids` as a Kotlin `Array<String>` of hex ids.
fn id_array(env: &mut JNIEnv<'_>, ids: Vec<EntityId>) -> Result<jobjectArray, String> {
    let count = jsize::try_from(ids.len()).map_err(display)?;
    let array = env
        .new_object_array(count, "java/lang/String", JObject::null())
        .map_err(display)?;
    for (index, id) in (0..count).zip(ids) {
        let id = env.new_string(id.to_hex()).map_err(display)?;
        env.set_object_array_element(&array, index, &id)
            .map_err(display)?;
        env.delete_local_ref(id).map_err(display)?;
    }
    Ok(array.into_raw())
}

/// `entries` as a Kotlin `Array<SubtreeEntry>`.
fn subtree_array(
    env: &mut JNIEnv<'_>,
    entries: Vec<(EntityId, u32)>,
) -> Result<jobjectArray, String> {
    let count = jsize::try_from(entries.len()).map_err(display)?;
    let array = env
        .new_object_array(count, "org/oneiron/SubtreeEntry", JObject::null())
        .map_err(display)?;
    for (index, (id, depth)) in (0..count).zip(entries) {
        let id = env.new_string(id.to_hex()).map_err(display)?;
        let depth = jint::try_from(depth).map_err(display)?;
        let element = env
            .new_object(
                "org/oneiron/SubtreeEntry",
                "(Ljava/lang/String;I)V",
                &[(&id).into(), JValue::Int(depth)],
            )
            .map_err(display)?;
        env.set_object_array_element(&array, index, &element)
            .map_err(display)?;
        env.delete_local_ref(id).map_err(display)?;
        env.delete_local_ref(element).map_err(display)?;
    }
    Ok(array.into_raw())
}

/// JNI context pack: UTF-8 in the format the Kotlin call names.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EmbeddedVault_contextPackNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
    text: JString<'_>,
    vector: JFloatArray<'_>,
    limit: jint,
    format: JString<'_>,
) -> jstring {
    run(&mut env, |env| {
        let text = optional_string(env, &text)?;
        let format = optional_string(env, &format)?;
        let vector = if vector.is_null() {
            None
        } else {
            Some(float_values(env, &vector)?)
        };
        let pack = {
            // SAFETY: same synchronized, private instance field as putNative.
            let vault: MutexGuard<'_, NativeVault> =
                unsafe { env.get_rust_field(&object, "nativeHandle") }.map_err(display)?;
            vault.context_pack(text.as_deref(), vector.as_deref(), limit, format.as_deref())?
        };
        env.new_string(pack).map(JString::into_raw).map_err(display)
    })
}

/// JNI text search: the `limit` best BM25 matches, best first.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EmbeddedVault_searchTextNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
    query: JString<'_>,
    limit: jint,
) -> jobjectArray {
    run(&mut env, |env| {
        let query: String = env.get_string(&query).map_err(display)?.into();
        let hits = {
            // SAFETY: same synchronized, private instance field as putNative.
            let vault: MutexGuard<'_, NativeVault> =
                unsafe { env.get_rust_field(&object, "nativeHandle") }.map_err(display)?;
            vault.search_text(&query, limit)?
        };
        scored_array(env, hits)
    })
}

/// The peers `object`'s vault reads for `id`, as a Kotlin `Array<String>`.
fn peers_native(
    env: &mut JNIEnv<'_>,
    object: &JObject<'_>,
    id: &JString<'_>,
    kind: jint,
    has_type: jboolean,
    peer_type: jint,
    inbound: bool,
) -> jobjectArray {
    run(env, |env| {
        let id: String = env.get_string(id).map_err(display)?.into();
        let peers = {
            // SAFETY: same synchronized, private instance field as putNative.
            let vault: MutexGuard<'_, NativeVault> =
                unsafe { env.get_rust_field(object, "nativeHandle") }.map_err(display)?;
            vault.peers(&id, kind, (has_type != 0).then_some(peer_type), inbound)?
        };
        id_array(env, peers)
    })
}

/// JNI targets: `src`'s outbound peers over `kind` edges.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EmbeddedVault_targetsNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
    src: JString<'_>,
    kind: jint,
    has_type: jboolean,
    target_type: jint,
) -> jobjectArray {
    peers_native(&mut env, &object, &src, kind, has_type, target_type, false)
}

/// JNI sources: `target`'s inbound peers over `kind` edges.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EmbeddedVault_sourcesNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
    target: JString<'_>,
    kind: jint,
    has_type: jboolean,
    source_type: jint,
) -> jobjectArray {
    peers_native(
        &mut env,
        &object,
        &target,
        kind,
        has_type,
        source_type,
        true,
    )
}

/// JNI subtree: `root`'s `ChildOf` descendants with their depths.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EmbeddedVault_subtreeNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
    root: JString<'_>,
    max_depth: jint,
) -> jobjectArray {
    run(&mut env, |env| {
        let root: String = env.get_string(&root).map_err(display)?.into();
        let entries = {
            // SAFETY: same synchronized, private instance field as putNative.
            let vault: MutexGuard<'_, NativeVault> =
                unsafe { env.get_rust_field(&object, "nativeHandle") }.map_err(display)?;
            vault.subtree(&root, max_depth)?
        };
        subtree_array(env, entries)
    })
}

/// JNI ancestors: `node`'s `ChildOf` ancestors.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_oneiron_EmbeddedVault_ancestorsNative(
    mut env: JNIEnv<'_>,
    object: JObject<'_>,
    node: JString<'_>,
) -> jobjectArray {
    run(&mut env, |env| {
        let node: String = env.get_string(&node).map_err(display)?.into();
        let ancestors = {
            // SAFETY: same synchronized, private instance field as putNative.
            let vault: MutexGuard<'_, NativeVault> =
                unsafe { env.get_rust_field(&object, "nativeHandle") }.map_err(display)?;
            vault.ancestors(&node)?
        };
        id_array(env, ancestors)
    })
}
