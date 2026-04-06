use anyhow::Result;
#[cfg(feature = "cryptowerk")]
use anyhow::anyhow;
use chrono::Utc;

use crate::{CryptowerkProof, RunMeta};

const DEFAULT_CRYPTOWERK_BASE_URL: &str = "https://developers.cryptowerk.com/platform";
const CRYPTOWERK_PERMALINK_BASE: &str =
    "https://developers.cryptowerk.com/platform/permalink/sealapiverify";
#[cfg(feature = "cryptowerk")]
const MAX_REGISTER_QUERY_CHARS: usize = 3000;

#[derive(Debug, Clone)]
pub struct CryptowerkConfig {
    pub base_url: String,
    pub api_key: Option<String>,
}

impl CryptowerkConfig {
    pub fn from_sources(
        enabled: bool,
        base_url: Option<String>,
        api_key: Option<String>,
    ) -> Option<Self> {
        if !enabled {
            return None;
        }

        Some(Self {
            base_url: base_url
                .or_else(|| std::env::var("CRYPTOWERK_BASE_URL").ok())
                .unwrap_or_else(|| DEFAULT_CRYPTOWERK_BASE_URL.to_string()),
            api_key: api_key.or_else(|| std::env::var("CRYPTOWERK_API_KEY").ok()),
        })
    }

    pub fn is_configured(&self) -> bool {
        self.api_key
            .as_deref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
    }
}

pub trait RunAnchor: Send + Sync {
    fn anchor_hash(&self, hash: &str) -> Result<Option<CryptowerkProof>>;

    fn anchor_hashes(&self, hashes: &[String]) -> Result<Vec<Option<CryptowerkProof>>> {
        hashes.iter().map(|hash| self.anchor_hash(hash)).collect()
    }

    fn anchor_completed_run(&self, meta: &RunMeta) -> Result<Option<CryptowerkProof>>;
}

pub struct NoopRunAnchor;

impl RunAnchor for NoopRunAnchor {
    fn anchor_hash(&self, _hash: &str) -> Result<Option<CryptowerkProof>> {
        Ok(None)
    }

    fn anchor_hashes(&self, hashes: &[String]) -> Result<Vec<Option<CryptowerkProof>>> {
        Ok(vec![None; hashes.len()])
    }

    fn anchor_completed_run(&self, _meta: &RunMeta) -> Result<Option<CryptowerkProof>> {
        Ok(None)
    }
}

pub fn build_run_anchor(config: Option<CryptowerkConfig>) -> Box<dyn RunAnchor> {
    match config {
        Some(config) if config.is_configured() => {
            #[cfg(feature = "cryptowerk")]
            {
                Box::new(CryptowerkRunAnchor::new(config))
            }
            #[cfg(not(feature = "cryptowerk"))]
            {
                let _ = config;
                Box::new(NoopRunAnchor)
            }
        }
        _ => Box::new(NoopRunAnchor),
    }
}

pub fn cryptowerk_permalink(retrieval_id: &str) -> String {
    format!("{CRYPTOWERK_PERMALINK_BASE}?retrievalId={retrieval_id}")
}

pub fn cryptowerk_failure(error_text: String) -> CryptowerkProof {
    CryptowerkProof {
        retrieval_id: None,
        proof_url: None,
        registered_at: Utc::now(),
        error_text: Some(error_text),
    }
}

#[cfg(feature = "cryptowerk")]
struct CryptowerkRunAnchor {
    client: reqwest::blocking::Client,
    config: CryptowerkConfig,
}

#[cfg(feature = "cryptowerk")]
impl CryptowerkRunAnchor {
    fn new(config: CryptowerkConfig) -> Self {
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(3))
            .timeout(std::time::Duration::from_secs(8))
            .build()
            .expect("valid reqwest client");
        Self { client, config }
    }

    fn register_url(&self) -> String {
        let mut base = self.config.base_url.trim_end_matches('/').to_string();
        if !base.contains("/API/") {
            base.push_str("/API/v8");
        }
        format!("{base}/register")
    }

    fn extract_retrieval_id(value: &serde_json::Value) -> Option<String> {
        for key in ["retrievalId", "retrieval_id"] {
            if let Some(id) = value.get(key).and_then(|item| item.as_str()) {
                return Some(id.to_string());
            }
        }

        if let Some(documents) = value.get("documents").and_then(|item| item.as_array()) {
            for document in documents {
                if let Some(id) = Self::extract_retrieval_id(document) {
                    return Some(id);
                }
            }
        }

        for key in ["data", "result", "response"] {
            if let Some(inner) = value.get(key) {
                if let Some(id) = Self::extract_retrieval_id(inner) {
                    return Some(id);
                }
            }
        }

        None
    }

    fn extract_retrieval_ids(value: &serde_json::Value) -> Option<Vec<String>> {
        if let Some(documents) = value.get("documents").and_then(|item| item.as_array()) {
            let ids: Option<Vec<String>> =
                documents.iter().map(Self::extract_retrieval_id).collect();
            if let Some(ids) = ids {
                return Some(ids);
            }
        }

        if let Some(id) = Self::extract_retrieval_id(value) {
            return Some(vec![id]);
        }

        for key in ["data", "result", "response"] {
            if let Some(inner) = value.get(key)
                && let Some(ids) = Self::extract_retrieval_ids(inner)
            {
                return Some(ids);
            }
        }

        None
    }

    fn register_hashes(&self, hashes: &[String]) -> Result<Vec<Option<CryptowerkProof>>> {
        if hashes.is_empty() {
            return Ok(Vec::new());
        }

        if hashes.len() > 1 {
            let mut all_proofs = Vec::with_capacity(hashes.len());
            let mut start = 0usize;
            while start < hashes.len() {
                let mut end = start;
                let mut query_len = "publiclyRetrievable=true".len();
                while end < hashes.len() {
                    let next_hash_len = if end == start {
                        hashes[end].len()
                    } else {
                        hashes[end].len() + 1
                    };
                    if end > start && query_len + next_hash_len > MAX_REGISTER_QUERY_CHARS {
                        break;
                    }
                    query_len += next_hash_len;
                    end += 1;
                }
                if end == start {
                    end += 1;
                }
                all_proofs.extend(self.register_hashes(&hashes[start..end])?);
                start = end;
            }
            return Ok(all_proofs);
        }

        let api_key = self
            .config
            .api_key
            .as_deref()
            .ok_or_else(|| anyhow!("missing Cryptowerk API key"))?;

        let response = self
            .client
            .get(self.register_url())
            .header("X-API-Key", api_key)
            .query(&[
                ("hashes", hashes.join(",")),
                ("publiclyRetrievable", "true".to_string()),
            ])
            .send()?;

        let status = response.status();
        let body = response.text()?;

        if !status.is_success() {
            if status == reqwest::StatusCode::BAD_REQUEST
                && body.contains("Request header is too large")
            {
                return Err(anyhow!(
                    "Cryptowerk register failed (400 Bad Request): request URL was too large for the server"
                ));
            }
            return Err(anyhow!("Cryptowerk register failed ({status}): {body}"));
        }

        let json: serde_json::Value = serde_json::from_str(&body)
            .map_err(|error| anyhow!("invalid Cryptowerk response: {error}"))?;
        let retrieval_ids = Self::extract_retrieval_ids(&json).ok_or_else(|| {
            anyhow!(
                "Cryptowerk response did not include retrievalId values. Expected fields like retrievalId or documents[].retrievalId; body: {body}"
            )
        })?;

        if retrieval_ids.len() != hashes.len() {
            return Err(anyhow!(
                "Cryptowerk returned {} retrieval IDs for {} hashes; body: {body}",
                retrieval_ids.len(),
                hashes.len()
            ));
        }

        let registered_at = Utc::now();
        Ok(retrieval_ids
            .into_iter()
            .map(|retrieval_id| {
                Some(CryptowerkProof {
                    retrieval_id: Some(retrieval_id.clone()),
                    proof_url: Some(cryptowerk_permalink(&retrieval_id)),
                    registered_at,
                    error_text: None,
                })
            })
            .collect())
    }
}

#[cfg(feature = "cryptowerk")]
impl RunAnchor for CryptowerkRunAnchor {
    fn anchor_hash(&self, hash: &str) -> Result<Option<CryptowerkProof>> {
        Ok(self
            .register_hashes(&[hash.to_string()])?
            .into_iter()
            .next()
            .flatten())
    }

    fn anchor_hashes(&self, hashes: &[String]) -> Result<Vec<Option<CryptowerkProof>>> {
        self.register_hashes(hashes)
    }

    fn anchor_completed_run(&self, meta: &RunMeta) -> Result<Option<CryptowerkProof>> {
        self.anchor_hash(&meta.root_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cryptowerk_config_uses_env_defaults() {
        let config = CryptowerkConfig::from_sources(false, None, None);
        assert!(config.is_none());
    }

    #[test]
    fn cryptowerk_permalink_uses_expected_shape() {
        let url = cryptowerk_permalink("ri_123");
        assert_eq!(
            url,
            "https://developers.cryptowerk.com/platform/permalink/sealapiverify?retrievalId=ri_123"
        );
    }

    #[cfg(feature = "cryptowerk")]
    #[test]
    fn extract_retrieval_id_handles_nested_payloads() {
        let payload = serde_json::json!({
            "data": {
                "retrievalId": "ri_nested"
            }
        });
        assert_eq!(
            CryptowerkRunAnchor::extract_retrieval_id(&payload).as_deref(),
            Some("ri_nested")
        );
    }

    #[cfg(feature = "cryptowerk")]
    #[test]
    fn extract_retrieval_id_handles_documents_array() {
        let payload = serde_json::json!({
            "minSupportedAPIVersion": 8,
            "maxSupportedAPIVersion": 6,
            "documents": [
                {
                    "retrievalId": "ri_document"
                }
            ]
        });
        assert_eq!(
            CryptowerkRunAnchor::extract_retrieval_id(&payload).as_deref(),
            Some("ri_document")
        );
    }
}
