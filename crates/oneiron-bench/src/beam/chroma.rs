//! Independent vanilla-RAG arm. No Vault or ContextPackBuilder reaches this module.
use super::{
    BeamError, BeamResult,
    load::decode_contract_vector,
    report_model::{ContractCorpusRecord, ContractEmbeddingState},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ChromaConfig {
    pub endpoint: String,
    pub retrieval_k: usize,
    pub card_id: String,
}
pub(super) struct ChromaArm {
    client: reqwest::blocking::Client,
    url: String,
    corpus: BTreeMap<String, String>,
    k: usize,
}
impl ChromaArm {
    pub(super) fn ingest(
        config: &ChromaConfig,
        corpus: &[ContractCorpusRecord],
    ) -> BeamResult<Self> {
        if config.retrieval_k == 0 || config.card_id.trim().is_empty() {
            return Err(refusal("Chroma requires retrieval_k and a card id"));
        }
        let url = reqwest::Url::parse(&config.endpoint)
            .map_err(|_| refusal("invalid Chroma endpoint"))?;
        let loopback = url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(refusal("Chroma endpoint must not contain credentials"));
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| refusal("Chroma client failed"))?;
        let collections = format!(
            "{}/tenants/default_tenant/databases/default_database/collections",
            config.endpoint.trim_end_matches('/')
        );
        let name = format!("beam-{}", oneiron::EntityId::now().to_hex());
        let created:serde_json::Value=client.post(&collections).json(&serde_json::json!({"name":name,"configuration":{"hnsw":{"space":"cosine"}},"get_or_create":false})).send().and_then(reqwest::blocking::Response::error_for_status).and_then(reqwest::blocking::Response::json).map_err(|_|refusal("Chroma collection creation failed"))?;
        let id = created["id"]
            .as_str()
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
            .ok_or_else(|| refusal("invalid Chroma collection id"))?;
        let arm = Self {
            client,
            url: format!("{collections}/{id}"),
            corpus: corpus
                .iter()
                .map(|c| (c.id.clone(), c.text.clone()))
                .collect(),
            k: config.retrieval_k,
        };
        if arm.corpus.len() != corpus.len() {
            return Err(refusal("duplicate Chroma corpus id"));
        }
        let embeddings = corpus
            .iter()
            .map(|c| match c.embedding.as_ref() {
                Some(ContractEmbeddingState::Ready(vector)) => {
                    decode_contract_vector(Path::new("chroma-corpus"), 0, vector)
                }
                _ => Err(refusal("Chroma requires ready corpus vectors")),
            })
            .collect::<BeamResult<Vec<_>>>()?;
        arm.client.post(format!("{}/add",arm.url)).json(&serde_json::json!({"ids":corpus.iter().map(|c|&c.id).collect::<Vec<_>>(),"documents":corpus.iter().map(|c|&c.text).collect::<Vec<_>>(),"embeddings":embeddings})).send().and_then(reqwest::blocking::Response::error_for_status).map_err(|_|refusal("Chroma ingest failed"))?;
        Ok(arm)
    }
    pub(super) fn retrieve(&self, query: &[f32]) -> BeamResult<String> {
        let response:serde_json::Value=self.client.post(format!("{}/query",self.url)).json(&serde_json::json!({"query_embeddings":[query],"n_results":self.k,"include":["distances"]})).send().and_then(reqwest::blocking::Response::error_for_status).and_then(reqwest::blocking::Response::json).map_err(|_|refusal("Chroma query failed"))?;
        let ids = response["ids"][0]
            .as_array()
            .ok_or_else(|| refusal("Chroma omitted result ids"))?;
        if ids.len() > self.k {
            return Err(refusal("Chroma exceeded retrieval_k"));
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut text = String::new();
        for value in ids {
            let id = value
                .as_str()
                .ok_or_else(|| refusal("invalid Chroma result id"))?;
            if !seen.insert(id) {
                return Err(refusal("duplicate Chroma result id"));
            }
            let source = self
                .corpus
                .get(id)
                .ok_or_else(|| refusal("Chroma returned an unknown document"))?;
            text.push_str(source);
            text.push('\n');
        }
        Ok(text)
    }
}
impl Drop for ChromaArm {
    fn drop(&mut self) {
        let _ = self.client.delete(&self.url).send();
    }
}
fn refusal(reason: &str) -> BeamError {
    BeamError::Comparability {
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests;
