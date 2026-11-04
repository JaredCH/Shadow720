//! OAuth 2.0 device authorization grant, so the user never leaves the app.
//!
//! # Why this exists
//!
//! Fine-grained personal access tokens **cannot be created through the API** —
//! GitHub has no endpoint for it, by design. Asking a user to open a browser,
//! navigate to a settings page, tick a dozen permission checkboxes, and paste a
//! string back is exactly the kind of setup step this app is trying to avoid.
//!
//! The device flow replaces all of that with one button. The user is shown a
//! short code and a URL, approves on any device they already have, and the app
//! polls until a token appears. No client secret is involved: the device grant is
//! designed for public clients, so the `client_id` can be embedded in the binary
//! without leaking anything sensitive.
//!
//! # What the token is
//!
//! The resulting token is an **OAuth user token**, not a fine-grained PAT. It is
//! account-scoped, which is what provisioning needs, and it is what the vault
//! stores. It is not scoped to a single repository, so the invite carries it with
//! the same caveat the PAT had: anyone holding an invite can act as the host
//! within the granted scopes. Rotation is the mitigation, as before.
//!
//! # Scopes
//!
//! `repo` covers issues, comments, releases, and release assets on private
//! repositories. `delete_repo` is requested separately and only when the host
//! opts into in-app "Destroy Group", because it is a destructive scope that
//! GitHub warns about.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{AppError, Result};

/// GitHub's device-code endpoint.
pub const GITHUB_DEVICE_CODE_URL: &str = "https://github.com/login/device/code";
/// GitHub's token endpoint, used to poll for the device grant.
pub const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
/// Where the user types the code.
pub const GITHUB_VERIFICATION_URL: &str = "https://github.com/login/device";

/// Scopes needed to run a group: issues, comments, releases, release assets.
pub const SCOPE_GROUP: &str = "repo";
/// Extra scope for in-app "Destroy Group". Destructive, so it is opt-in.
pub const SCOPE_DESTROY: &str = "delete_repo";

/// Minimum interval between polls, per RFC 8628 §3.5.
const MIN_POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Hard ceiling on a single poll request.
const POLL_TIMEOUT: Duration = Duration::from_secs(30);

/// A pending device authorization.
#[derive(Clone, Debug, Deserialize)]
pub struct DeviceCode {
    /// Opaque code the app polls with. Never shown to the user.
    pub device_code: String,
    /// Short code the user types at [`GITHUB_VERIFICATION_URL`].
    pub user_code: String,
    /// Page the user should open.
    pub verification_uri: String,
    /// Seconds until the code expires.
    pub expires_in: u64,
    /// Minimum seconds between polls.
    pub interval: u64,
}

/// A completed device authorization.
#[derive(Clone, Debug)]
pub struct DeviceToken {
    /// The access token. Zeroized on drop.
    pub access_token: Zeroizing<String>,
    /// Scopes GitHub actually granted, which can be narrower than requested.
    pub scope: String,
    /// `bearer` or `token`, depending on how GitHub issued it.
    pub token_type: String,
}

/// Why a poll did not produce a token yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PollOutcome {
    /// The user has not approved yet; keep polling at the same interval.
    Pending,
    /// GitHub asked us to slow down; add five seconds to the interval.
    SlowDown,
}

/// Raw token-endpoint response. GitHub returns `200` even for errors, with an
/// `error` field instead of `access_token`.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

/// Client for the device authorization grant.
///
/// Holds no secret: the `client_id` is public by design for this flow.
pub struct DeviceFlowClient {
    http: reqwest::Client,
    client_id: String,
    device_code_url: String,
    token_url: String,
}

impl std::fmt::Debug for DeviceFlowClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceFlowClient")
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

impl DeviceFlowClient {
    /// Build a client for GitHub's public endpoints.
    pub fn new(client_id: impl Into<String>) -> Result<Self> {
        Self::with_endpoints(
            client_id,
            GITHUB_DEVICE_CODE_URL,
            GITHUB_TOKEN_URL,
        )
    }

    /// Build against custom endpoints, for GitHub Enterprise or tests.
    pub fn with_endpoints(
        client_id: impl Into<String>,
        device_code_url: impl Into<String>,
        token_url: impl Into<String>,
    ) -> Result<Self> {
        let client_id: String = client_id.into();
        if client_id.trim().is_empty() {
            return Err(AppError::not_configured(
                "no OAuth client id is configured, so account sign-in is unavailable",
            ));
        }

        let http = reqwest::Client::builder()
            .user_agent(concat!("shadow720/", env!("CARGO_PKG_VERSION")))
            .timeout(POLL_TIMEOUT)
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| AppError::network("oauth", format!("could not build HTTP client: {e}")))?;

        Ok(Self {
            http,
            client_id,
            device_code_url: device_code_url.into(),
            token_url: token_url.into(),
        })
    }

    /// Start a device authorization and return the code to show the user.
    pub async fn request_device_code(&self, scopes: &[&str]) -> Result<DeviceCode> {
        let scope = scopes.join(" ");
        let response = self
            .http
            .post(&self.device_code_url)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&[("client_id", self.client_id.as_str()), ("scope", scope.as_str())])
            .send()
            .await
            .map_err(|e| {
                AppError::network(
                    self.device_code_url.clone(),
                    format!("could not start device authorization: {e}"),
                )
            })?;

        let status = response.status();
        let body = response.bytes().await.map_err(|e| {
            AppError::network("oauth", format!("could not read device code response: {e}"))
        })?;

        if !status.is_success() {
            return Err(AppError::GitHubApi {
                status: status.as_u16(),
                message: crate::github_db::extract_error_message(&body)
                    .unwrap_or_else(|| "device authorization was rejected".into()),
            });
        }

        let code: DeviceCode = serde_json::from_slice(&body).map_err(|e| {
            AppError::parse(self.device_code_url.clone(), format!("invalid JSON: {e}"))
        })?;

        if code.device_code.trim().is_empty() || code.user_code.trim().is_empty() {
            return Err(AppError::parse(
                self.device_code_url.clone(),
                "device authorization response was missing a code",
            ));
        }

        Ok(code)
    }

    /// Poll once for the token.
    ///
    /// Returns [`PollOutcome`] while the user has not approved yet, and the token
    /// once they have. Errors that need user action (denied, expired) come back
    /// as `Err` so the caller can stop polling and say why.
    pub async fn poll_once(&self, device_code: &str) -> Result<std::result::Result<DeviceToken, PollOutcome>> {
        let response = self
            .http
            .post(&self.token_url)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("device_code", device_code),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ])
            .send()
            .await
            .map_err(|e| {
                AppError::network(
                    self.token_url.clone(),
                    format!("could not poll for the device token: {e}"),
                )
            })?;

        let status = response.status();
        let body = response.bytes().await.map_err(|e| {
            AppError::network("oauth", format!("could not read token response: {e}"))
        })?;

        if !status.is_success() {
            return Err(AppError::GitHubApi {
                status: status.as_u16(),
                message: crate::github_db::extract_error_message(&body)
                    .unwrap_or_else(|| "token request was rejected".into()),
            });
        }

        let parsed: TokenResponse = serde_json::from_slice(&body).map_err(|e| {
            AppError::parse(self.token_url.clone(), format!("invalid JSON: {e}"))
        })?;

        if let Some(token) = parsed.access_token {
            if token.trim().is_empty() {
                return Err(AppError::parse(
                    self.token_url.clone(),
                    "token response contained an empty access token",
                ));
            }
            return Ok(Ok(DeviceToken {
                access_token: Zeroizing::new(token),
                scope: parsed.scope.unwrap_or_default(),
                token_type: parsed.token_type.unwrap_or_else(|| "bearer".into()),
            }));
        }

        match parsed.error.as_deref() {
            // The two "keep waiting" signals from RFC 8628 §3.5.
            Some("authorization_pending") => Ok(Err(PollOutcome::Pending)),
            Some("slow_down") => Ok(Err(PollOutcome::SlowDown)),
            Some("expired_token") => Err(AppError::GitHubAuth { status: 410 }),
            Some("access_denied") => Err(AppError::GitHubAuth { status: 403 }),
            Some(other) => Err(AppError::GitHubApi {
                status: status.as_u16(),
                message: parsed
                    .error_description
                    .unwrap_or_else(|| format!("device authorization failed: {other}")),
            }),
            None => Err(AppError::parse(
                self.token_url.clone(),
                "token response had neither a token nor an error",
            )),
        }
    }

    /// Poll until the user approves, the code expires, or `deadline` passes.
    ///
    /// Sleeps between attempts, honouring `slow_down` by widening the interval.
    pub async fn wait_for_token(
        &self,
        code: &DeviceCode,
        deadline: Duration,
    ) -> Result<DeviceToken> {
        let mut interval = Duration::from_secs(code.interval.max(MIN_POLL_INTERVAL.as_secs()));
        let started = std::time::Instant::now();

        loop {
            if started.elapsed() >= deadline {
                return Err(AppError::GitHubAuth { status: 408 });
            }

            match self.poll_once(&code.device_code).await? {
                Ok(token) => return Ok(token),
                Err(PollOutcome::Pending) => {}
                Err(PollOutcome::SlowDown) => {
                    interval += Duration::from_secs(5);
                }
            }

            tokio::time::sleep(interval).await;
        }
    }
}

/// Scopes to request for a group, optionally including the destructive one.
pub fn scopes_for_group(allow_destroy: bool) -> Vec<&'static str> {
    if allow_destroy {
        vec![SCOPE_GROUP, SCOPE_DESTROY]
    } else {
        vec![SCOPE_GROUP]
    }
}

/// Wire shape of a pending authorization, for the UI.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceCodeResponse {
    /// Short code the user types at `verificationUri`.
    pub user_code: String,
    /// Page the user should open.
    pub verification_uri: String,
    /// Seconds until the code expires.
    pub expires_in: u64,
    /// Minimum seconds between polls.
    pub interval: u64,
}

impl From<&DeviceCode> for DeviceCodeResponse {
    fn from(code: &DeviceCode) -> Self {
        Self {
            user_code: code.user_code.clone(),
            verification_uri: code.verification_uri.clone(),
            expires_in: code.expires_in,
            interval: code.interval,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_rejects_an_empty_client_id() {
        assert!(DeviceFlowClient::new("").is_err());
        assert!(DeviceFlowClient::new("   ").is_err());
    }

    #[test]
    fn client_accepts_a_public_client_id() {
        let client = DeviceFlowClient::new("Iv1.abc123").expect("client");
        assert_eq!(client.client_id, "Iv1.abc123");
    }

    #[test]
    fn debug_never_prints_a_token() {
        let client = DeviceFlowClient::new("Iv1.abc123").expect("client");
        let rendered = format!("{client:?}");
        assert!(rendered.contains("Iv1.abc123"));
        assert!(!rendered.contains("access_token"));
    }

    #[test]
    fn scopes_include_destroy_only_when_asked() {
        assert_eq!(scopes_for_group(false), vec!["repo"]);
        assert_eq!(scopes_for_group(true), vec!["repo", "delete_repo"]);
    }

    #[test]
    fn device_code_response_maps_to_the_wire_shape() {
        let code = DeviceCode {
            device_code: "secret".into(),
            user_code: "ABCD-1234".into(),
            verification_uri: GITHUB_VERIFICATION_URL.into(),
            expires_in: 900,
            interval: 5,
        };
        let wire = DeviceCodeResponse::from(&code);
        assert_eq!(wire.user_code, "ABCD-1234");
        assert_eq!(wire.expires_in, 900);
        // The device code itself must never reach the UI.
        let json = serde_json::to_string(&wire).expect("serialize");
        assert!(!json.contains("secret"));
    }

    #[test]
    fn token_response_parses_a_success() {
        let json = r#"{"access_token":"gho_x","scope":"repo","token_type":"bearer"}"#;
        let parsed: TokenResponse = serde_json::from_str(json).expect("parse");
        assert_eq!(parsed.access_token.as_deref(), Some("gho_x"));
        assert!(parsed.error.is_none());
    }

    #[test]
    fn token_response_parses_a_pending_error() {
        let json = r#"{"error":"authorization_pending"}"#;
        let parsed: TokenResponse = serde_json::from_str(json).expect("parse");
        assert!(parsed.access_token.is_none());
        assert_eq!(parsed.error.as_deref(), Some("authorization_pending"));
    }
}
