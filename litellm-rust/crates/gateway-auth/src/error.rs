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
