//! Unified error type for the whole application.
//!
//! Every fallible operation in this crate returns [`Result`] with [`AppError`].
//! Runtime code must never panic: no `unwrap()`, no `expect()`, no indexing that
//! can go out of bounds. Errors are surfaced to the TypeScript layer through
//! `serde::Serialize`, so each variant carries a stable, machine-readable
//! [`AppErrorKind`] alongside a human message.

use serde::{Serialize, Serializer};

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, AppError>;

/// Stable, machine-readable classification of every failure mode.
///
/// The TypeScript layer switches on these strings for UI decisions, so the
/// values are part of the public contract and must not be renamed casually.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppErrorKind {
    /// Cryptographic failure: bad tag, bad signature, malformed key material.
    Crypto,
    /// Invite string (`GRP1-...`) is malformed, truncated, or wrong version.
    InviteFormat,
    /// Join password did not unwrap the invite payload (AEAD tag mismatch).
    InvitePassword,
    /// GitHub REST returned a non-success status.
    GitHubApi,
    /// GitHub rejected the request because the token is invalid or expired.
    GitHubAuth,
    /// GitHub secondary/primary rate limit reached; caller must back off.
    RateLimited,
    /// Network transport failure: DNS, TLS, timeout, connection reset.
    Network,
    /// HTTP response was not valid JSON or did not match the expected shape.
    ResponseParse,
    /// Payload exceeded a configured size ceiling (file or comment).
    PayloadTooLarge,
    /// Storage vault is unavailable or its wrapping key was invalidated.
    VaultUnavailable,
    /// Caller-supplied argument failed validation.
    InvalidArgument,
    /// Group state is missing, stale, or refers to a rotated-out key epoch.
    GroupState,
    /// Local or OS-level I/O failure.
    Io,
    /// A required integration has not been configured yet (e.g. missing PAT).
    NotConfigured,
}

impl AppErrorKind {
    /// Stable wire string for this kind, matching the serde representation.
    pub fn as_str(self) -> &'static str {
        match self {
            AppErrorKind::Crypto => "crypto",
            AppErrorKind::InviteFormat => "invite_format",
            AppErrorKind::InvitePassword => "invite_password",
            AppErrorKind::GitHubApi => "github_api",
            AppErrorKind::GitHubAuth => "github_auth",
            AppErrorKind::RateLimited => "rate_limited",
            AppErrorKind::Network => "network",
            AppErrorKind::ResponseParse => "response_parse",
            AppErrorKind::PayloadTooLarge => "payload_too_large",
            AppErrorKind::VaultUnavailable => "vault_unavailable",
            AppErrorKind::InvalidArgument => "invalid_argument",
            AppErrorKind::GroupState => "group_state",
            AppErrorKind::Io => "io",
            AppErrorKind::NotConfigured => "not_configured",
        }
    }
}

/// The application error type.
///
/// `#[error(...)]` strings become the user-facing message. Variants deliberately
/// avoid interpolating secrets: `repo_scoped_pat` must never end up in a log or
/// an error surfaced to the UI.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("invite string is malformed: {0}")]
    InviteFormat(String),

    #[error("join password is incorrect")]
    InvitePassword,

    #[error("GitHub API error {status}: {message}")]
    GitHubApi { status: u16, message: String },

    #[error("GitHub authentication failed (HTTP {status}); the token may be expired or under-scoped")]
    GitHubAuth { status: u16 },

    #[error("GitHub rate limit reached; retry after {reset_unix_s} (unix seconds)")]
    RateLimited { reset_unix_s: i64, remaining: u32 },

    #[error("network request to {url} failed: {source_message}")]
    Network {
        url: String,
        source_message: String,
    },

    #[error("could not parse GitHub response for {endpoint}: {reason}")]
    ResponseParse { endpoint: String, reason: String },

    #[error("{what} is {actual_bytes} bytes, which exceeds the {limit_bytes} byte limit")]
    PayloadTooLarge {
        what: &'static str,
        actual_bytes: u64,
        limit_bytes: u64,
    },

    #[error("secure storage is unavailable: {0}")]
    VaultUnavailable(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("group state problem: {0}")]
    GroupState(String),

    #[error("i/o error during {context}: {source_message}")]
    Io {
        context: &'static str,
        source_message: String,
    },

    #[error("{0}")]
    NotConfigured(String),
}

impl AppError {
    /// Machine-readable classification for the TypeScript layer.
    pub fn kind(&self) -> AppErrorKind {
        match self {
            AppError::Crypto(_) => AppErrorKind::Crypto,
            AppError::InviteFormat(_) => AppErrorKind::InviteFormat,
            AppError::InvitePassword => AppErrorKind::InvitePassword,
            AppError::GitHubApi { .. } => AppErrorKind::GitHubApi,
            AppError::GitHubAuth { .. } => AppErrorKind::GitHubAuth,
            AppError::RateLimited { .. } => AppErrorKind::RateLimited,
            AppError::Network { .. } => AppErrorKind::Network,
            AppError::ResponseParse { .. } => AppErrorKind::ResponseParse,
            AppError::PayloadTooLarge { .. } => AppErrorKind::PayloadTooLarge,
            AppError::VaultUnavailable(_) => AppErrorKind::VaultUnavailable,
            AppError::InvalidArgument(_) => AppErrorKind::InvalidArgument,
            AppError::GroupState(_) => AppErrorKind::GroupState,
            AppError::Io { .. } => AppErrorKind::Io,
            AppError::NotConfigured(_) => AppErrorKind::NotConfigured,
        }
    }

    /// True when the caller should wait before retrying.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            AppError::Network { .. } | AppError::RateLimited { .. }
        )
    }

    /// True when the failure is the user's fault and deserves a UI prompt rather
    /// than a silent retry.
    pub fn is_user_actionable(&self) -> bool {
        matches!(
            self,
            AppError::InvitePassword
                | AppError::InviteFormat(_)
                | AppError::GitHubAuth { .. }
                | AppError::VaultUnavailable(_)
                | AppError::NotConfigured(_)
                | AppError::InvalidArgument(_)
        )
    }

    /// Convenience constructors that keep call sites free of `format!` noise.
    pub fn crypto(msg: impl Into<String>) -> Self {
        AppError::Crypto(msg.into())
    }

    pub fn invalid_argument(msg: impl Into<String>) -> Self {
        AppError::InvalidArgument(msg.into())
    }

    pub fn group_state(msg: impl Into<String>) -> Self {
        AppError::GroupState(msg.into())
    }

    pub fn vault(msg: impl Into<String>) -> Self {
        AppError::VaultUnavailable(msg.into())
    }

    pub fn not_configured(msg: impl Into<String>) -> Self {
        AppError::NotConfigured(msg.into())
    }

    pub fn io(context: &'static str, source_message: impl Into<String>) -> Self {
        AppError::Io {
            context,
            source_message: source_message.into(),
        }
    }

    pub fn network(url: impl Into<String>, source_message: impl Into<String>) -> Self {
        AppError::Network {
            url: url.into(),
            source_message: source_message.into(),
        }
    }

    pub fn parse(endpoint: impl Into<String>, reason: impl Into<String>) -> Self {
        AppError::ResponseParse {
            endpoint: endpoint.into(),
            reason: reason.into(),
        }
    }
}

/// `std::io::Error` is common enough that a blanket conversion keeps call sites
/// readable. The context string is generic because `From` cannot know the
/// caller's intent; use [`AppError::io`] where the context matters.
impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::Io {
            context: "io",
            source_message: err.to_string(),
        }
    }
}

/// Serialize as `{ "kind": "...", "message": "..." }`.
///
/// Tauri requires command errors to be `Serialize`; emitting a flat object keeps
/// the TS side simple (`err.kind === "rate_limited"`).
impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("AppError", 2)?;
        state.serialize_field("kind", self.kind().as_str())?;
        state.serialize_field("message", &self.to_string())?;
                state.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_mapping_is_exhaustive() {
        let cases: Vec<(AppError, AppErrorKind)> = vec![
            (AppError::Crypto("x".into()), AppErrorKind::Crypto),
            (AppError::InviteFormat("x".into()), AppErrorKind::InviteFormat),
            (AppError::InvitePassword, AppErrorKind::InvitePassword),
            (
                AppError::GitHubApi {
                    status: 404,
                    message: "nope".into(),
                },
                AppErrorKind::GitHubApi,
            ),
            (AppError::GitHubAuth { status: 401 }, AppErrorKind::GitHubAuth),
            (
                AppError::RateLimited {
                    reset_unix_s: 0,
                    remaining: 0,
                },
                AppErrorKind::RateLimited,
            ),
            (
                AppError::Network {
                    url: "u".into(),
                    source_message: "s".into(),
                },
                AppErrorKind::Network,
            ),
            (
                AppError::ResponseParse {
                    endpoint: "e".into(),
                    reason: "r".into(),
                },
                AppErrorKind::ResponseParse,
            ),
            (
                AppError::PayloadTooLarge {
                    what: "file",
                    actual_bytes: 2,
                    limit_bytes: 1,
                },
                AppErrorKind::PayloadTooLarge,
            ),
            (
                AppError::VaultUnavailable("v".into()),
                AppErrorKind::VaultUnavailable,
            ),
            (
                AppError::InvalidArgument("a".into()),
                AppErrorKind::InvalidArgument,
            ),
            (AppError::GroupState("g".into()), AppErrorKind::GroupState),
            (
                AppError::Io {
                    context: "c",
                    source_message: "s".into(),
                },
                AppErrorKind::Io,
            ),
            (
                AppError::NotConfigured("n".into()),
                AppErrorKind::NotConfigured,
            ),
        ];

        for (err, expected) in cases {
            assert_eq!(err.kind(), expected, "mismatch for {err:?}");
        }
    }

    #[test]
    fn serializes_to_kind_and_message() {
        let err = AppError::RateLimited {
            reset_unix_s: 1_700_000_000,
            remaining: 0,
        };
        let json = serde_json::to_value(&err).expect("serialize");
        assert_eq!(json["kind"], "rate_limited");
        assert!(
            json["message"]
                .as_str()
                .is_some_and(|m| m.contains("1700000000")),
            "message should include the reset time: {json:?}"
        );
    }

    #[test]
    fn retryable_and_actionable_classification() {
        assert!(AppError::network("u", "s").is_retryable());
        assert!(
            AppError::RateLimited {
                reset_unix_s: 0,
                remaining: 0
            }
            .is_retryable()
        );
        assert!(!AppError::Crypto("x".into()).is_retryable());

        assert!(AppError::InvitePassword.is_user_actionable());
        assert!(AppError::GitHubAuth { status: 401 }.is_user_actionable());
        assert!(!AppError::GitHubApi {
            status: 500,
            message: "oops".into()
        }
        .is_user_actionable());
    }

    #[test]
    fn io_error_conversion_preserves_message() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing file");
        let app_err: AppError = io_err.into();
        assert_eq!(app_err.kind(), AppErrorKind::Io);
        assert!(app_err.to_string().contains("missing file"));
    }

    #[test]
    fn errors_never_contain_secrets_in_message() {
        // Guards the contract that tokens are not interpolated into messages.
        let err = AppError::GitHubAuth { status: 401 };
        let rendered = err.to_string();
        assert!(!rendered.contains("ghp_"));
        assert!(!rendered.contains("github_pat_"));
    }
}