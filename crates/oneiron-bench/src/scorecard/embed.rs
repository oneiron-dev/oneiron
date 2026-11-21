//! `scorecard pack-embed`: fill one pack slice's vectors from the served embedder.
//!
//! Records embed as documents, queries as queries, through the served
//! `oneiron-server embedder serve` route; every row goes through the served
//! numerics contract before the slice is pinned.

use oneiron_ruler::pack::{Vectors, load_slice, write_slice};

use super::{ScorecardFailure, parse_flags, parse_slice, required_flag};

/// The flags `scorecard pack-embed` takes.
const KNOWN_FLAGS: &[&str] = &["pack-dir", "slice", "endpoint", "model-id", "batch"];

/// The served embedder endpoint when `--endpoint` is omitted.
const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:7399";

/// Texts per embeddings request when `--batch` is omitted.
const DEFAULT_BATCH: usize = 64;

/// The most texts one embeddings request may carry.
const MAX_BATCH: usize = 2048;

/// The HTTP timeout of every embedder request, in seconds.
const HTTP_TIMEOUT_SECS: u64 = 600;

/// The served model row `/v1/models` admits the endpoint by.
struct ListedModel {
    /// The row id requests name as their model.
    id: String,
    /// The served embedding space.
    model_id: String,
    /// The vector width every row must have.
    dimensions: usize,
    /// How the served vectors are made.
    transform: String,
    /// The run profile the row names, if any.
    profile: Option<serde_json::Value>,
}

/// Embed every record then every query of one slice, pin the finished vectors.
pub(crate) fn run(args: &[String]) -> Result<serde_json::Value, ScorecardFailure> {
    let flags = parse_flags(args, KNOWN_FLAGS)?;
    let slice = parse_slice(required_flag(&flags, "slice")?)?;
    let pack_dir = required_flag(&flags, "pack-dir")?;
    let batch = flag_batch(flags.get("batch").map(String::as_str))?;
    let endpoint = flags
        .get("endpoint")
        .map_or(DEFAULT_ENDPOINT, String::as_str);
    let wanted_model = flags.get("model-id").map(String::as_str);
    let mut loaded = load_slice(std::path::Path::new(pack_dir), slice)
        .map_err(|error| ScorecardFailure::Input(error.to_string()))?;
    let endpoint = endpoint.trim_end_matches('/');
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(HTTP_TIMEOUT_SECS))
        .build()
        .map_err(|error| ScorecardFailure::Run(format!("embedder client failed: {error}")))?;
    let listed = list_model(&client, endpoint)?;
    if let Some(wanted) = wanted_model
        && wanted != listed.model_id.as_str()
    {
        let served = &listed.model_id;
        return Err(ScorecardFailure::Run(format!(
            "endpoint serves {served} but --model-id wants {wanted}"
        )));
    }
    let mut data = Vec::new();
    for chunk in loaded.slice.records.chunks(batch) {
        let texts: Vec<&str> = chunk.iter().map(|record| record.text.as_str()).collect();
        data.extend(embed_batch(&client, endpoint, &listed, &texts, "document")?);
    }
    for chunk in loaded.slice.queries.chunks(batch) {
        let texts: Vec<&str> = chunk.iter().map(|query| query.text.as_str()).collect();
        data.extend(embed_batch(&client, endpoint, &listed, &texts, "query")?);
    }
    let vectors = Vectors::new(listed.dimensions, data)
        .map_err(|error| ScorecardFailure::Run(error.to_string()))?;
    loaded
        .slice
        .pin_vectors(&listed.model_id, &listed.transform, &vectors)
        .map_err(|error| ScorecardFailure::Run(error.to_string()))?;
    let pack_digest = write_slice(
        std::path::Path::new(pack_dir),
        &loaded.slice,
        Some(&vectors),
    )
    .map_err(|error| ScorecardFailure::Run(error.to_string()))?;
    Ok(serde_json::json!({
        "slice": slice.as_str(),
        "rows": vectors.rows(),
        "dims": vectors.dims(),
        "model_id": listed.model_id,
        "transform": listed.transform,
        "vectors_sha256": vectors.sha256_hex(),
        "pack_digest": pack_digest,
    }))
}

/// Parse the optional `--batch` flag with its default and range.
fn flag_batch(raw: Option<&str>) -> Result<usize, ScorecardFailure> {
    let Some(text) = raw else {
        return Ok(DEFAULT_BATCH);
    };
    match text.parse::<usize>() {
        Ok(batch) if (1..=MAX_BATCH).contains(&batch) => Ok(batch),
        _ => Err(ScorecardFailure::Input(format!(
            "--batch must be an integer 1..={MAX_BATCH}, got {text:?}"
        ))),
    }
}

/// Read the one `oneiron_wire` row of `/v1/models`.
fn list_model(
    client: &reqwest::blocking::Client,
    endpoint: &str,
) -> Result<ListedModel, ScorecardFailure> {
    let url = format!("{endpoint}/v1/models");
    let response = client
        .get(&url)
        .send()
        .map_err(|error| ScorecardFailure::Run(format!("GET {url} failed: {error}")))?;
    let body = read_json(response, &url)?;
    let Some(rows) = body.get("data").and_then(serde_json::Value::as_array) else {
        return Err(ScorecardFailure::Run(format!(
            "GET {url} answered no model list"
        )));
    };
    let mut wire = Vec::new();
    for row in rows {
        if row.get("oneiron_wire").and_then(serde_json::Value::as_u64) == Some(1) {
            wire.push(row);
        }
    }
    let [row] = wire.as_slice() else {
        let found = wire.len();
        return Err(ScorecardFailure::Run(format!(
            "GET {url} listed {found} oneiron_wire rows, want exactly one"
        )));
    };
    let id = text_field(row, "id", &url)?;
    let model_id = text_field(row, "model_id", &url)?;
    let transform = text_field(row, "transform", &url)?;
    let dimensions = row
        .get("dimensions")
        .and_then(serde_json::Value::as_u64)
        .and_then(|wide| usize::try_from(wide).ok())
        .filter(|dims| *dims > 0);
    let Some(dimensions) = dimensions else {
        return Err(ScorecardFailure::Run(format!(
            "GET {url} listed bad dimensions"
        )));
    };
    Ok(ListedModel {
        id,
        model_id,
        dimensions,
        transform,
        profile: row.get("profile").cloned(),
    })
}

/// Read a text field of a `/v1/models` row.
fn text_field(row: &serde_json::Value, name: &str, url: &str) -> Result<String, ScorecardFailure> {
    row.get(name)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| ScorecardFailure::Run(format!("GET {url} row misses {name}")))
}

/// Read one embedder answer: a successful status and a JSON body.
fn read_json(
    response: reqwest::blocking::Response,
    url: &str,
) -> Result<serde_json::Value, ScorecardFailure> {
    let status = response.status();
    if !status.is_success() {
        return Err(ScorecardFailure::Run(format!(
            "{url} answered HTTP {status}"
        )));
    }
    response
        .json::<serde_json::Value>()
        .map_err(|error| ScorecardFailure::Run(format!("{url} answered invalid JSON: {error}")))
}

/// Embed one batch of texts as one side, and finish every row.
fn embed_batch(
    client: &reqwest::blocking::Client,
    endpoint: &str,
    listed: &ListedModel,
    texts: &[&str],
    input_type: &str,
) -> Result<Vec<f32>, ScorecardFailure> {
    let url = format!("{endpoint}/v1/embeddings");
    let request = serde_json::json!({
        "model": listed.id.as_str(),
        "input": texts,
        "encoding_format": "float",
        "input_type": input_type,
    });
    let response = client
        .post(&url)
        .json(&request)
        .send()
        .map_err(|error| ScorecardFailure::Run(format!("POST {url} failed: {error}")))?;
    let body = read_json(response, &url)?;
    if body.get("error").is_some() {
        return Err(ScorecardFailure::Run(format!(
            "POST {url} answered an error member"
        )));
    }
    check_answer_agrees(&body, listed, &url)?;
    let Some(rows) = body.get("data").and_then(serde_json::Value::as_array) else {
        return Err(ScorecardFailure::Run(format!(
            "POST {url} answered no data"
        )));
    };
    if rows.len() != texts.len() {
        let (got, want) = (rows.len(), texts.len());
        return Err(ScorecardFailure::Run(format!(
            "POST {url} answered {got} rows for {want} inputs"
        )));
    }
    let mut ordered: Vec<Option<&serde_json::Value>> = Vec::new();
    ordered.resize(rows.len(), None);
    for row in rows {
        let index = row
            .get("index")
            .and_then(serde_json::Value::as_u64)
            .and_then(|wide| usize::try_from(wide).ok());
        let Some(index) = index else {
            return Err(ScorecardFailure::Run(format!(
                "POST {url} answered a row with a bad index"
            )));
        };
        let Some(slot) = ordered.get_mut(index) else {
            let want = texts.len();
            return Err(ScorecardFailure::Run(format!(
                "POST {url} answered index {index} for {want} inputs"
            )));
        };
        if slot.is_some() {
            return Err(ScorecardFailure::Run(format!(
                "POST {url} repeated index {index}"
            )));
        }
        *slot = Some(row);
    }
    let mut out = Vec::with_capacity(texts.len() * listed.dimensions);
    for slot in ordered {
        let Some(row) = slot else {
            return Err(ScorecardFailure::Run(format!(
                "POST {url} left an input unanswered"
            )));
        };
        let Some(embedding) = row.get("embedding").and_then(serde_json::Value::as_array) else {
            return Err(ScorecardFailure::Run(format!(
                "POST {url} answered a non-float embedding"
            )));
        };
        let mut vector = Vec::with_capacity(embedding.len());
        for value in embedding {
            let Some(number) = value.as_f64() else {
                return Err(ScorecardFailure::Run(format!(
                    "POST {url} answered a non-numeric component"
                )));
            };
            vector.push(number as f32);
        }
        out.extend(finish_vector(vector, listed.dimensions, &url)?);
    }
    Ok(out)
}

/// Refuse an answer that names another model id, transform or profile than
/// the `/v1/models` row: vectors made under another transform would be pinned
/// as the listed one. The engine's endpoint client asks the same of every
/// `embedder serve` answer (oneiron-server/src/embedder/endpoint.rs,
/// `agrees_with`).
fn check_answer_agrees(
    body: &serde_json::Value,
    listed: &ListedModel,
    url: &str,
) -> Result<(), ScorecardFailure> {
    let model_id = body.get("model_id").and_then(serde_json::Value::as_str);
    if model_id != Some(listed.model_id.as_str()) {
        let listed_model_id = &listed.model_id;
        return Err(ScorecardFailure::Run(format!(
            "POST {url} answered model_id {model_id:?}, the listing names {listed_model_id:?}"
        )));
    }
    let transform = body.get("transform").and_then(serde_json::Value::as_str);
    if transform != Some(listed.transform.as_str()) {
        let listed_transform = &listed.transform;
        return Err(ScorecardFailure::Run(format!(
            "POST {url} answered transform {transform:?}, the listing names {listed_transform:?}"
        )));
    }
    if body.get("profile") != listed.profile.as_ref() {
        return Err(ScorecardFailure::Run(format!(
            "POST {url} answered another profile than the listing names"
        )));
    }
    Ok(())
}

/// The served numerics contract, copying the embedder's own arithmetic: exact
/// width, finite components, a finite non-zero norm, then each component
/// divided by the norm and rounded through f16.
fn finish_vector(
    mut vector: Vec<f32>,
    dimensions: usize,
    url: &str,
) -> Result<Vec<f32>, ScorecardFailure> {
    if vector.len() != dimensions {
        let got = vector.len();
        return Err(ScorecardFailure::Run(format!(
            "POST {url} answered width {got}, want {dimensions}"
        )));
    }
    for (index, value) in vector.iter().enumerate() {
        if !value.is_finite() {
            return Err(ScorecardFailure::Run(format!(
                "POST {url} answered a non-finite component at {index}"
            )));
        }
    }
    let norm = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
    if !norm.is_finite() || norm <= 0.0 {
        return Err(ScorecardFailure::Run(format!(
            "POST {url} answered a vector with norm {norm}"
        )));
    }
    for value in &mut vector {
        let scaled = *value / norm;
        let narrowed = half::f16::from_f32(scaled);
        if !narrowed.is_finite() {
            return Err(ScorecardFailure::Run(format!(
                "POST {url} answered a component that leaves f16: {scaled}"
            )));
        }
        *value = narrowed.to_f32();
    }
    Ok(vector)
}
