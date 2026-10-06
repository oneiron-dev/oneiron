//! Item 11: real-dimension vectors and a map size scaled to the corpus.

#[cfg(test)]
mod tests {
    use super::super::tests_contract_v2::tests::{V2Fixture, corpus_jsonl, v2_corpus_items};
    use super::super::util::{VaultShape, scaled_map_size};
    use super::super::*;

    fn b64(bytes: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(TABLE[((n >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    /// A unit vector along axis `hot` in `dims` dimensions, f32-LE base64.
    fn vector(dims: usize, hot: usize) -> serde_json::Value {
        let bytes: Vec<u8> = (0..dims)
            .flat_map(|i| if i == hot { 1.0_f32 } else { 0.0 }.to_le_bytes())
            .collect();
        serde_json::json!({"encoding": "f32-le-base64", "dimensions": dims, "data": b64(&bytes)})
    }

    /// Rewrites a v2 fixture to carry `dims`-wide vectors everywhere.
    fn widen(fixture: &V2Fixture, dims: usize, query_dims: usize) {
        let mut items = v2_corpus_items();
        for (index, item) in items.iter_mut().enumerate() {
            item["embedding"] = vector(dims, index);
        }
        let corpus = corpus_jsonl(&items);
        std::fs::write(&fixture.corpus_path, &corpus).unwrap();
        let old = super::super::load::sha256_hex(corpus_jsonl(&v2_corpus_items()).as_bytes());
        let new = super::super::load::sha256_hex(corpus.as_bytes());
        let rows: Vec<String> = std::fs::read_to_string(&fixture.run_jsonl)
            .unwrap()
            .lines()
            .map(|line| {
                let mut record: serde_json::Value = serde_json::from_str(line).unwrap();
                record["query_embedding"] = vector(query_dims, 0);
                record.to_string().replace(&old, &new)
            })
            .collect();
        std::fs::write(&fixture.run_jsonl, rows.join("\n") + "\n").unwrap();
    }

    fn manifest_with(fixture: &V2Fixture, extra: serde_json::Value) -> RunManifest {
        let mut raw: serde_json::Value =
            serde_json::from_str(super::super::tests_community_eval004::CONTRACT_MANIFEST_JSON)
                .unwrap();
        raw["runId"] = serde_json::json!(super::super::tests_contract_v2::tests::V2_RUN_ID);
        raw["dataset"]["path"] = serde_json::json!(fixture.run_jsonl);
        raw["caseIds"] = serde_json::json!(["q-a"]);
        raw["outputs"]["packsJsonl"] = serde_json::json!(fixture.packs_jsonl);
        for (key, value) in extra.as_object().unwrap() {
            raw["dataset"][key] = value.clone();
        }
        parse_manifest_json(&raw.to_string()).unwrap()
    }

    #[test]
    fn e5_base_width_vectors_run_through_both_arms() {
        let fixture = V2Fixture::write(&["q-a"]);
        widen(&fixture, 768, 768);
        let manifest = manifest_with(
            &fixture,
            serde_json::json!({"embeddingModel": "intfloat/multilingual-e5-base@fixture"}),
        );
        run_manifest(&manifest, None).expect("768-dim run");
        let rows: Vec<serde_json::Value> = std::fs::read_to_string(&fixture.packs_jsonl)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let vanilla = rows
            .iter()
            .find(|row| row["arm"]["kind"] == "vanilla-rag")
            .expect("vanilla row");
        assert_eq!(vanilla["pack"]["config"]["vectorDimensions"], 768);
        assert_eq!(
            vanilla["pack"]["config"]["embedderId"],
            "intfloat/multilingual-e5-base@fixture"
        );
        assert!(
            vanilla["pack"]["contexts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|context| context["id"] == "m-1"),
            "the 768-dim vector leg retrieves"
        );
    }

    #[test]
    fn mixed_widths_and_a_contradicting_manifest_are_refused() {
        let fixture = V2Fixture::write(&["q-a"]);
        widen(&fixture, 768, 384);
        let error = run_manifest(&manifest_with(&fixture, serde_json::json!({})), None)
            .expect_err("two widths in one run")
            .to_string();
        assert!(error.contains("mix vector widths"), "{error}");

        let fixture = V2Fixture::write(&["q-a"]);
        widen(&fixture, 768, 768);
        let error = run_manifest(
            &manifest_with(&fixture, serde_json::json!({"embeddingDimensions": 1024})),
            None,
        )
        .expect_err("manifest says 1024")
        .to_string();
        assert!(error.contains("embeddingDimensions is 1024"), "{error}");

        let fixture = V2Fixture::write(&["q-a"]);
        let error = run_manifest(
            &manifest_with(
                &fixture,
                serde_json::json!({"embeddingModel": "multilingual-e5"}),
            ),
            None,
        )
        .expect_err("an embedder id without org and revision")
        .to_string();
        assert!(error.contains("org/name@revision"), "{error}");
    }

    #[test]
    fn four_dim_fixtures_keep_the_default_shape() {
        let fixture = V2Fixture::write(&["q-a"]);
        let manifest = fixture.manifest(&["q-a"]);
        let path = std::path::Path::new(&fixture.run_jsonl);
        let mut entries =
            super::super::load::select_run_jsonl_records(&manifest, path, None).unwrap();
        super::super::load::resolve_corpus_refs(path, &mut entries).unwrap();
        let shape = super::super::load::contract_vault_shape(&manifest, path, &entries).unwrap();
        let default = VaultShape::default_contract();
        assert_eq!(shape.dimensions, default.dimensions);
        assert_eq!(shape.embedding_model, default.embedding_model);
        assert!(shape.map_size >= default.map_size);
    }

    #[test]
    fn map_size_scales_with_the_corpus_and_never_drops_below_32_mib() {
        const MIB: usize = 1024 * 1024;
        assert_eq!(
            scaled_map_size(0, 0),
            64 * MIB,
            "rounded up to one 64 MiB step"
        );
        // One books-set novel: 1.6 MB of text, 1,500 paragraphs at 768 dims.
        let novel = scaled_map_size(1_600_000, 1_500 * 768);
        assert!(
            novel >= 128 * MIB && novel.is_multiple_of(64 * MIB),
            "{novel}"
        );
        // A BEAM-10M chat: about 40 MB of text.
        assert!(scaled_map_size(40_000_000, 0) > 2_000 * MIB);
        assert!(scaled_map_size(1_000, 0) >= 32 * MIB);
    }
}
