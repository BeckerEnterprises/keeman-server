//! Errors as RFC 9457 problem details with the API's error codes. Handlers
//! return [`ApiError`]; the problem finaliser in `app.rs` renders the body,
//! because only it knows the request ID (`instance`).

use std::fmt::Display;

use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};

macro_rules! error_codes {
    ($($variant:ident => ($code:literal, $status:ident, $title:literal),)*) => {
        /// Machine-readable error codes, the `code` of every problem response.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
        pub enum ErrorCode { #[default] $($variant,)* }

        impl ErrorCode {
            pub const ALL: &'static [ErrorCode] = &[$(ErrorCode::$variant,)*];

            pub fn as_str(self) -> &'static str {
                match self { $(ErrorCode::$variant => $code,)* }
            }

            pub fn status(self) -> StatusCode {
                match self { $(ErrorCode::$variant => StatusCode::$status,)* }
            }

            pub fn title(self) -> &'static str {
                match self { $(ErrorCode::$variant => $title,)* }
            }
        }
    };
}

error_codes! {
    ValidationFailed => ("validation_failed", BAD_REQUEST, "Invalid request"),
    UrlNotAllowed => ("url_not_allowed", BAD_REQUEST, "URL not allowed"),
    InvalidCredentials => ("invalid_credentials", UNAUTHORIZED, "Invalid credentials"),
    InvalidSecondFactor => ("invalid_second_factor", UNAUTHORIZED, "Invalid second factor"),
    ChallengeInvalid => ("challenge_invalid", UNAUTHORIZED, "Challenge invalid"),
    SessionInvalid => ("session_invalid", UNAUTHORIZED, "Session invalid"),
    ReauthRequired => ("reauth_required", UNAUTHORIZED, "Reauthentication required"),
    Forbidden => ("forbidden", FORBIDDEN, "Forbidden"),
    RegistrationClosed => ("registration_closed", FORBIDDEN, "Registration closed"),
    InviteInvalid => ("invite_invalid", FORBIDDEN, "Invite invalid"),
    AccountDisabled => ("account_disabled", FORBIDDEN, "Account disabled"),
    NotFound => ("not_found", NOT_FOUND, "Not found"),
    UserNotFound => ("user_not_found", NOT_FOUND, "User not found"),
    FeatureDisabled => ("feature_disabled", NOT_FOUND, "Feature disabled"),
    MethodNotAllowed => ("method_not_allowed", METHOD_NOT_ALLOWED, "Method not allowed"),
    RequestTimeout => ("request_timeout", REQUEST_TIMEOUT, "Request timeout"),
    Conflict => ("conflict", CONFLICT, "Conflict"),
    RefreshSuperseded => ("refresh_superseded", CONFLICT, "Refresh superseded"),
    RotationInvalid => ("rotation_invalid", CONFLICT, "Rotation invalid"),
    RotationInProgress => ("rotation_in_progress", CONFLICT, "An open rotation removes the caller"),
    StaleKeyVersion => ("stale_key_version", CONFLICT, "Stale key version"),
    KeyVersionMismatch => ("key_version_mismatch", CONFLICT, "Key version mismatch"),
    EmailTaken => ("email_taken", CONFLICT, "E-mail already registered"),
    AlreadyRegistered => ("already_registered", CONFLICT, "Already registered"),
    AlreadyMember => ("already_member", CONFLICT, "Already a member"),
    LastOwner => ("last_owner", CONFLICT, "Last owner"),
    SoleOwnerOfSharedVault => ("sole_owner_of_shared_vault", CONFLICT, "Sole owner of a shared vault"),
    UseRotate => ("use_rotate", CONFLICT, "Use a key rotation"),
    TwoFactorStateInvalid => ("two_factor_state_invalid", CONFLICT, "Two-factor state invalid"),
    RolesConflict => ("roles_conflict", CONFLICT, "Roles statement does not follow the head"),
    OwnerMustDemote => ("owner_must_demote", CONFLICT, "Owner must demote itself first"),
    SigningKeyMissing => ("signing_key_missing", CONFLICT, "Signing key missing"),
    ResyncRequired => ("resync_required", GONE, "Resync required"),
    PayloadTooLarge => ("payload_too_large", PAYLOAD_TOO_LARGE, "Payload too large"),
    AttachmentTooLarge => ("attachment_too_large", PAYLOAD_TOO_LARGE, "Attachment too large"),
    UnsupportedMediaType => ("unsupported_media_type", UNSUPPORTED_MEDIA_TYPE, "Unsupported media type"),
    RangeNotSatisfiable => ("range_not_satisfiable", RANGE_NOT_SATISFIABLE, "Range not satisfiable"),
    KdfParamsInvalid => ("kdf_params_invalid", UNPROCESSABLE_ENTITY, "KDF parameters invalid"),
    RotationIncomplete => ("rotation_incomplete", UNPROCESSABLE_ENTITY, "Rotation incomplete"),
    FaviconNotFound => ("favicon_not_found", UNPROCESSABLE_ENTITY, "Favicon not found"),
    IdempotencyKeyReused => ("idempotency_key_reused", UNPROCESSABLE_ENTITY, "Idempotency key reused"),
    AttachmentIncomplete => ("attachment_incomplete", UNPROCESSABLE_ENTITY, "Attachment incomplete"),
    ManifestRequired => ("manifest_required", UNPROCESSABLE_ENTITY, "Manifest required"),
    RolesRequired => ("roles_required", UNPROCESSABLE_ENTITY, "Roles statement required"),
    RateLimited => ("rate_limited", TOO_MANY_REQUESTS, "Too many requests"),
    InternalError => ("internal_error", INTERNAL_SERVER_ERROR, "Internal error"),
    QuotaExceeded => ("quota_exceeded", INSUFFICIENT_STORAGE, "Quota exceeded"),
}

impl ErrorCode {
    /// Code used when a response without problem body has this status.
    pub fn for_status(status: StatusCode) -> ErrorCode {
        match status {
            StatusCode::BAD_REQUEST => ErrorCode::ValidationFailed,
            StatusCode::UNAUTHORIZED => ErrorCode::SessionInvalid,
            StatusCode::FORBIDDEN => ErrorCode::Forbidden,
            StatusCode::NOT_FOUND => ErrorCode::NotFound,
            StatusCode::METHOD_NOT_ALLOWED => ErrorCode::MethodNotAllowed,
            StatusCode::REQUEST_TIMEOUT => ErrorCode::RequestTimeout,
            StatusCode::PAYLOAD_TOO_LARGE => ErrorCode::PayloadTooLarge,
            StatusCode::UNSUPPORTED_MEDIA_TYPE => ErrorCode::UnsupportedMediaType,
            StatusCode::TOO_MANY_REQUESTS => ErrorCode::RateLimited,
            _ => ErrorCode::InternalError,
        }
    }
}

/// One entry of `errors[]`; `detail` is always a fixed text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldError {
    Pointer {
        pointer: String,
        detail: &'static str,
    },
    Parameter {
        parameter: &'static str,
        detail: &'static str,
    },
}

/// One entry of `conflicts[]` of a batch conflict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    pub id: String,
    pub current_revision: Option<i64>,
    pub deleted: bool,
}

/// Problem data attached to a response; rendered by the finaliser.
#[derive(Debug, Clone, Default)]
pub struct ProblemData {
    pub code: ErrorCode,
    pub detail: Option<&'static str>,
    pub errors: Vec<FieldError>,
    pub current_revision: Option<i64>,
    pub current_key_version: Option<i64>,
    pub current_roles_version: Option<i64>,
    pub conflicts: Vec<Conflict>,
}

impl ProblemData {
    /// The problem body without `instance`; the finaliser adds it.
    /// Also the stored form of an idempotent answer.
    pub fn body(&self, status: StatusCode) -> Map<String, Value> {
        let mut body = Map::new();
        body.insert("title".into(), json!(self.code.title()));
        body.insert("status".into(), json!(status.as_u16()));
        body.insert("code".into(), json!(self.code.as_str()));
        if let Some(detail) = self.detail {
            body.insert("detail".into(), json!(detail));
        }
        if !self.errors.is_empty() {
            let errors: Vec<Value> = self
                .errors
                .iter()
                .map(|e| match e {
                    FieldError::Pointer { pointer, detail } => {
                        json!({ "pointer": pointer, "detail": detail })
                    }
                    FieldError::Parameter { parameter, detail } => {
                        json!({ "parameter": parameter, "detail": detail })
                    }
                })
                .collect();
            body.insert("errors".into(), Value::Array(errors));
        }
        if !self.conflicts.is_empty() {
            let conflicts: Vec<Value> = self
                .conflicts
                .iter()
                .map(|c| json!({ "id": c.id, "current_revision": c.current_revision, "deleted": c.deleted }))
                .collect();
            body.insert("conflicts".into(), Value::Array(conflicts));
        }
        if let Some(revision) = self.current_revision {
            body.insert("current_revision".into(), json!(revision));
        }
        if let Some(version) = self.current_key_version {
            body.insert("current_key_version".into(), json!(version));
        }
        if let Some(version) = self.current_roles_version {
            body.insert("current_roles_version".into(), json!(version));
        }
        body
    }
}

/// A stored problem body (without `instance`) replayed for a repeated
/// idempotent request; the finaliser only adds `instance`.
#[derive(Debug, Clone)]
pub struct StoredProblem(pub Map<String, Value>);

#[derive(Debug)]
pub struct ApiError {
    problem: Box<ProblemData>,
    retry_after: Option<u64>,
    set_cookie: Option<String>,
    header: Option<(HeaderName, HeaderValue)>,
}

impl ApiError {
    pub fn new(code: ErrorCode) -> Self {
        Self {
            problem: Box::new(ProblemData {
                code,
                ..ProblemData::default()
            }),
            retry_after: None,
            set_cookie: None,
            header: None,
        }
    }

    pub fn code(&self) -> ErrorCode {
        self.problem.code
    }

    pub fn problem(&self) -> &ProblemData {
        &self.problem
    }

    pub fn detail(mut self, detail: &'static str) -> Self {
        self.problem.detail = Some(detail);
        self
    }

    /// `400 validation_failed` pointing into the body.
    pub fn pointer(pointer: impl Into<String>, detail: &'static str) -> Self {
        let mut error = Self::new(ErrorCode::ValidationFailed);
        error.problem.errors.push(FieldError::Pointer {
            pointer: pointer.into(),
            detail,
        });
        error
    }

    /// `400 validation_failed` for a header, path or query parameter.
    pub fn parameter(parameter: &'static str, detail: &'static str) -> Self {
        let mut error = Self::new(ErrorCode::ValidationFailed);
        error
            .problem
            .errors
            .push(FieldError::Parameter { parameter, detail });
        error
    }

    pub fn current_revision(mut self, revision: i64) -> Self {
        self.problem.current_revision = Some(revision);
        self
    }

    pub fn current_key_version(mut self, version: i64) -> Self {
        self.problem.current_key_version = Some(version);
        self
    }

    /// `409 roles_conflict` with the version of the stored head (0 without one).
    pub fn roles_conflict(head_version: i64) -> Self {
        let mut error = Self::new(ErrorCode::RolesConflict);
        error.problem.current_roles_version = Some(head_version);
        error
    }

    /// `409 conflict` of a batch with the complete conflict list.
    pub fn conflicts(conflicts: Vec<Conflict>) -> Self {
        let mut error = Self::new(ErrorCode::Conflict);
        error.problem.conflicts = conflicts;
        error
    }

    pub fn retry_after(mut self, seconds: u64) -> Self {
        self.retry_after = Some(seconds.max(1));
        self
    }

    pub fn set_cookie(mut self, cookie: String) -> Self {
        self.set_cookie = Some(cookie);
        self
    }

    /// One more response header, e.g. `Content-Range` of a `416`.
    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.header = Some((name, value));
        self
    }

    /// Logs the cause (never shown to clients) and returns `500 internal_error`.
    pub fn internal(cause: impl Display) -> Self {
        tracing::error!(error = %cause, "internal error");
        Self::new(ErrorCode::InternalError)
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        Self::internal(error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = self.problem.code.status().into_response();
        if let Some(seconds) = self.retry_after {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(seconds));
        }
        if let Some(cookie) = self.set_cookie.and_then(|c| HeaderValue::from_str(&c).ok()) {
            response.headers_mut().append(header::SET_COOKIE, cookie);
        }
        if let Some((name, value)) = self.header {
            response.headers_mut().insert(name, value);
        }
        response.extensions_mut().insert(*self.problem);
        response
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
