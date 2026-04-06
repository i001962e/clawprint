use anyhow::Result;
#[cfg(feature = "cryptowerk")]
use anyhow::anyhow;
use chrono::Utc;

use crate::{CryptowerkProof, RunMeta};

const DEFAULT_CRYPTOWERK_BASE_URL: &str = "https://developers.cryptowerk.com/platform";
const CRYPTOWERK_PERMALINK_BASE: &str =
    "https://developers.cryptowerk.com/platform/permalink/sealapiverify";

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
    fn anchor_completed_run(&self, meta: &RunMeta) -> Result<Option<CryptowerkProof>>;
}

pub struct NoopRunAnchor;

impl RunAnchor for NoopRunAnchor {
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

    fn register_url(&self, root_hash: &str) -> String {
        let mut base = self.config.base_url.trim_end_matches('/').to_string();
        if !base.contains("/API/") {
            base.push_str("/API/v8");
        }
        format!("{base}/register?hashes={root_hash}&publiclyRetrievable=true")
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
}

#[cfg(feature = "cryptowerk")]
impl RunAnchor for CryptowerkRunAnchor {
    fn anchor_completed_run(&self, meta: &RunMeta) -> Result<Option<CryptowerkProof>> {
        let api_key = self
            .config
            .api_key
            .as_deref()
            .ok_or_else(|| anyhow!("missing Cryptowerk API key"))?;

        let response = self
            .client
            .get(self.register_url(&meta.root_hash))
            .header("X-API-Key", api_key)
            .send()?;

        let status = response.status();
        let body = response.text()?;

        if !status.is_success() {
            return Err(anyhow!("Cryptowerk register failed ({status}): {body}"));
        }

        let json: serde_json::Value = serde_json::from_str(&body)
            .map_err(|error| anyhow!("invalid Cryptowerk response: {error}"))?;
        let retrieval_id = Self::extract_retrieval_id(&json).ok_or_else(|| {
            anyhow!(
                "Cryptowerk response did not include retrievalId. Expected fields like retrievalId or documents[0].retrievalId; body: {body}"
            )
        })?;

        Ok(Some(CryptowerkProof {
            retrieval_id: Some(retrieval_id.clone()),
            proof_url: Some(cryptowerk_permalink(&retrieval_id)),
            registered_at: Utc::now(),
            error_text: None,
        }))
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
