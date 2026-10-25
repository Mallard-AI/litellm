use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("missing or invalid virtual key")]
    Invalid,
    #[error("virtual key has expired")]
    Expired,
    #[error("virtual key lookup unavailable")]
    Lookup(#[source] Box<dyn std::error::Error + Send + Sync>),
}

#[derive(Clone, Debug, thiserror::Error, Eq, PartialEq)]
pub enum PolicyConstructionError {
    #[error("invalid model pattern {pattern}: {detail}")]
    InvalidModelPattern { pattern: String, detail: String },
    #[error("unsupported route pattern {0}")]
    UnsupportedRoutePattern(String),
    #[error("unsupported model sentinel in an expanded grant")]
    UnsupportedModelSentinel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error, strum::VariantArray)]
pub enum Denial {
    #[error("key policy expired")]
    Expired,
    #[error("key is blocked")]
    KeyBlocked,
    #[error("team is blocked")]
    TeamBlocked,
    #[error("key model access denied")]
    KeyModelDenied,
    #[error("team model access denied")]
    TeamModelDenied,
    #[error("user model access denied")]
    UserModelDenied,
    #[error("team member model access denied")]
    MemberModelDenied,
    #[error("route access denied")]
    RouteDenied,
    #[error("request type is unsupported")]
    UnsupportedRequest,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("key store backend failed: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("key cache failed: {0}")]
    Cache(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl StoreError {
    pub fn backend<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Backend(Box::new(error))
    }

    pub fn cache<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Cache(Box::new(error))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidationError {
    #[error("invalidation JSON must be an object")]
    NotObject,
    #[error("invalidation JSON is malformed: {0}")]
    Malformed(String),
    #[error("invalidation cache_key must be a non-empty string")]
    InvalidCacheKey,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("key digest must be 64 lowercase hexadecimal characters")]
pub struct KeyHashError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("operation is not permitted")]
    Forbidden,
    #[error("credential has expired")]
    Expired,
    #[error("authenticated request context is missing")]
    MissingIdentity,
    #[error("authentication service unavailable")]
    Unavailable,
    #[error("gateway auth not configured")]
    Unconfigured,
    #[error("missing or invalid bearer token")]
    InvalidToken,
    #[error("gateway authentication unavailable")]
    Secret(#[from] litellm_secrets::Error),
}

impl Error {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::InvalidToken | Self::Expired => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::MissingIdentity | Self::Unconfigured | Self::Secret(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (self.status(), self.to_string()).into_response()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UiAuthError {
    #[error("UI_USERNAME and UI_PASSWORD must be nonempty")]
    Unconfigured,
    #[error("invalid UI credentials or session")]
    Unauthorized,
    #[error("UI authentication unavailable")]
    Unavailable,
    #[error("UI session unavailable")]
    Session(#[from] tower_sessions::session::Error),
}

impl IntoResponse for UiAuthError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, self.to_string()).into_response()
    }
}
