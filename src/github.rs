use std::sync::Arc;

use http::Uri;
use keyring::Entry;
use kunobi_jev::reqwest::header::ACCEPT;
use octocrab::{
    Octocrab,
    auth::OAuth,
    models::{pulls, repos::DiffEntry},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_env::from_env_with_prefix;
use thiserror::Error;

use crate::targets::PullRequest;

const KEYRING_SERVICE: &str = "sentinel-cli";
const KEYRING_ACCOUNT: &str = "oauth";

// scopes needed to review PR details, and repo context
const SCOPES: &[&str] = &["repo", "read:org"];

#[derive(Clone, Deserialize)]
struct GithubClientConfig {
    pat: Option<SecretString>,
    uat: Option<SecretString>,
    #[serde(rename = "client_id")]
    client_id: Option<SecretString>,
}

pub(crate) struct GithubClient {
    config: GithubClientConfig,
    octocrab: Option<Arc<Octocrab>>,
}

#[derive(Debug, Error)]
pub(crate) enum GithubClientError {
    #[error("Missing Github token")]
    MissingGithubToken,

    #[error("None, or multiple Github tokens provided")]
    MultipleGithubTokens,

    #[error("Missing Octocrab instance")]
    MissingOctocrab,

    #[error("Unable to load config: {0}")]
    ConfigLoadError(#[from] serde_env::Error),

    #[error("Octocrab error: {0}")]
    OctocrabError(#[from] octocrab::Error),

    #[error("Keyring error: {0}")]
    KeyringError(#[from] keyring::Error),

    #[error("unable to make request: {0}")]
    RequestError(#[from] reqwest::Error),

    #[error("Unable to serialize auth cache: {0}")]
    CacheSerializeError(#[from] serde_json::Error),
}

pub type PullRequestDetails = (pulls::PullRequest, Vec<DiffEntry>);

impl GithubClient {
    pub fn new() -> Result<Self, GithubClientError> {
        let config = from_env_with_prefix("GITHUB")?;

        Ok(Self {
            config,
            octocrab: None,
        })
    }

    pub async fn auth(&mut self) -> Result<(), GithubClientError> {
        let config = self.config.clone();
        let mut builder = Octocrab::builder();
        builder = match (config.pat, config.uat, &config.client_id) {
            (Some(token), None, None) => builder.personal_token(token),
            (None, Some(token), None) => builder.user_access_token(token),
            (None, None, Some(client_id)) => {
                if let Some((auth, expired)) = fetch_cached_github_auth() {
                    builder.oauth(self.oauth(&auth, expired).await?)
                } else {
                    let crab = Octocrab::builder()
                        .base_uri("https://github.com")?
                        .add_header(ACCEPT, "application/json".to_string())
                        .build()?;
                    let codes = crab.authenticate_as_device(client_id, SCOPES).await?;

                    clout::info!(
                        "Please visit {} and enter the code: {}",
                        codes.verification_uri,
                        codes.user_code
                    );
                    let auth = codes.poll_until_available(&crab, client_id).await?;
                    cache_github_auth(&auth)?;

                    Octocrab::builder().oauth(self.oauth(&auth, false).await?)
                }
            }
            (None, None, None) => {
                if let Some((auth, expired)) = fetch_cached_github_auth() {
                    builder.oauth(self.oauth(&auth, expired).await?)
                } else {
                    return Err(GithubClientError::MissingGithubToken);
                }
            }
            _ => return Err(GithubClientError::MultipleGithubTokens),
        };

        let octocrab = Some(Arc::new(builder.build()?));

        self.octocrab = octocrab;
        Ok(())
    }

    pub(crate) async fn fetch_pr(
        &self,
        pr: &PullRequest,
    ) -> Result<PullRequestDetails, GithubClientError> {
        let pr_number = pr.pr_number as u64;

        let client = self
            .octocrab
            .as_ref()
            .ok_or(GithubClientError::MissingOctocrab)?;

        let pr_details = client
            .pulls(pr.owner.clone(), pr.repo.clone())
            .get(pr_number)
            .await
            .map_err(GithubClientError::OctocrabError)?;

        let files = client
            .pulls(pr.owner.clone(), pr.repo.clone())
            .list_files(pr_number)
            .await
            .map_err(GithubClientError::OctocrabError)?;
        files.clone().into_iter().for_each(|file| {
            clout::debug!(
                "Changed file: {} ({} lines added, {} lines removed)",
                file.filename,
                file.additions,
                file.deletions
            );
        });

        Ok((pr_details, files.into_iter().collect()))
    }

    async fn oauth(&self, auth: &OAuth, expired: bool) -> Result<OAuth, GithubClientError> {
        if !expired {
            return Ok(auth.clone());
        }

        let client = reqwest::Client::new();

        clout::info!("Refreshing expired Github OAuth token...");

        let refreshed = client
            .post("https://github.com/login/oauth/access_token")
            .header(ACCEPT, "application/json")
            .form(&[
                ("grant_type", "refresh_token"),
                (
                    "refresh_token",
                    auth.refresh_token.as_ref().unwrap().expose_secret(),
                ),
                (
                    "client_id",
                    self.config.client_id.as_ref().unwrap().expose_secret(),
                ),
                ("scope", SCOPES.join(" ").as_str()),
            ])
            .send()
            .await?
            .json::<OAuth>()
            .await?;

        cache_github_auth(&refreshed)?;

        Ok(refreshed)
    }
}

/// Single-entry keyring payload. One keychain item means one unlock prompt
/// instead of one per field.
#[derive(Debug, Serialize, Deserialize)]
struct CachedAuth {
    access_token: String,
    token_type: String,
    scope: Vec<String>,
    refresh_token: Option<String>,
    // Absolute unix timestamps, derived from the relative `expires_in`
    // values Github returns.
    expires_at: Option<i64>,
    refresh_token_expires_at: Option<i64>,
}

impl CachedAuth {
    fn from_oauth(auth: &OAuth) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            access_token: auth.access_token.expose_secret().to_owned(),
            token_type: auth.token_type.clone(),
            scope: auth.scope.clone(),
            refresh_token: auth
                .refresh_token
                .as_ref()
                .map(|rt| rt.expose_secret().to_owned()),
            expires_at: auth.expires_in.map(|secs| now + secs as i64),
            refresh_token_expires_at: auth.refresh_token_expires_in.map(|secs| now + secs as i64),
        }
    }

    fn into_oauth(self) -> OAuth {
        let now = chrono::Utc::now();
        let remaining = |ts: i64| {
            chrono::DateTime::from_timestamp(ts, 0)
                .map(|dt| (dt - now).num_seconds().max(0) as usize)
        };
        OAuth {
            access_token: SecretString::new(self.access_token.into_boxed_str()),
            token_type: self.token_type,
            scope: self.scope,
            refresh_token: self
                .refresh_token
                .map(|rt| SecretString::new(rt.into_boxed_str())),
            expires_in: self.expires_at.and_then(remaining),
            refresh_token_expires_in: self.refresh_token_expires_at.and_then(remaining),
        }
    }
}

fn cache_github_auth(auth: &OAuth) -> Result<(), GithubClientError> {
    let entry = Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)?;
    let json = serde_json::to_string(&CachedAuth::from_oauth(auth))?;
    entry.set_secret(json.as_bytes())?;

    Ok(())
}

fn fetch_cached_github_auth() -> Option<(OAuth, bool)> {
    let entry = Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT).ok()?;
    let secret = entry.get_secret().ok()?;
    let auth = serde_json::from_slice::<CachedAuth>(&secret)
        .ok()
        .map(CachedAuth::into_oauth);

    if let Some(cached) = &auth {
        if cached.expires_in <= Some(0) {
            let _ = entry.delete_credential();

            return Some((cached.clone(), true));
        }

        Some((cached.clone(), false))
    } else {
        let _ = entry.delete_credential();
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oauth_cache_round_trip() {
        let auth = OAuth {
            access_token: SecretString::from("access-token"),
            token_type: "bearer".to_string(),
            scope: vec!["repo".to_string(), "read:org".to_string()],
            expires_in: Some(3600),
            refresh_token: Some(SecretString::from("refresh")),
            refresh_token_expires_in: Some(7200),
        };
        let json = serde_json::to_string(&CachedAuth::from_oauth(&auth)).unwrap();
        let back = serde_json::from_slice::<CachedAuth>(json.as_bytes())
            .unwrap()
            .into_oauth();
        assert_eq!(back.access_token.expose_secret(), "access-token");
        assert_eq!(back.token_type, "bearer");
        assert_eq!(back.scope, vec!["repo", "read:org"]);
        assert_eq!(back.refresh_token.unwrap().expose_secret(), "refresh");
        assert!((3599..=3600).contains(&back.expires_in.unwrap()));
        assert!((7199..=7200).contains(&back.refresh_token_expires_in.unwrap()));
    }

    #[test]
    fn expired_cache_clamps_to_zero() {
        let cached = CachedAuth {
            access_token: "x".to_string(),
            token_type: "bearer".to_string(),
            scope: vec![],
            refresh_token: None,
            expires_at: Some(chrono::Utc::now().timestamp() - 60),
            refresh_token_expires_at: None,
        };
        let back = cached.into_oauth();
        assert_eq!(back.expires_in, Some(0));
        assert_eq!(back.refresh_token_expires_in, None);
    }
}
