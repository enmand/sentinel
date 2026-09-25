use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{queries::Query, thresholds::Thresholds, value::Value};

const SENTINEL_VERSION: u8 = 1;

#[derive(Debug, Serialize, Deserialize)]
pub struct Sentinel {
    pub version: u8,
    pub questions: Option<Query>,
    pub thresholds: Option<Thresholds>,
    pub data: Option<Value>,
    pub policy: Option<PathBuf>,
}

impl Default for Sentinel {
    fn default() -> Self {
        Self {
            version: SENTINEL_VERSION,
            questions: None,
            thresholds: None,
            data: None,
            policy: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    Read(#[from] std::io::Error),

    #[error("Failed to parse config file: {0}")]
    Parse(#[from] serde_yaml::Error),

    #[error("Failed to load config from environment: {0}")]
    Env(#[from] serde_env::Error),
}

impl Sentinel {
    pub(crate) async fn load(path: Option<PathBuf>) -> Result<Sentinel, ConfigError> {
        #[derive(Serialize, Deserialize)]
        struct _Sentinel {
            version: Option<u8>,
            questions: Option<Query>,
            thresholds: Option<Thresholds>,
            data: Option<Value>,
            policy: Option<PathBuf>,
        }

        let config = if let Some(p) = path {
            let config_str = tokio::fs::read_to_string(&p).await?;
            let file_config: _Sentinel = serde_yaml::from_str(&config_str)?;

            Sentinel {
                version: file_config.version.unwrap_or(SENTINEL_VERSION),
                questions: file_config.questions,
                thresholds: file_config.thresholds,
                data: file_config.data,
                policy: file_config.policy,
            }
        } else {
            Sentinel::default()
        };
        let env_config: _Sentinel = serde_env::from_env_with_prefix("SENTINEL")?;

        let config = Sentinel {
            version: config.version,
            questions: env_config.questions.or(config.questions),
            thresholds: env_config.thresholds.or(config.thresholds),
            data: env_config.data.or(config.data),
            policy: env_config.policy.or(config.policy),
        };

        Ok(config)
    }
}
