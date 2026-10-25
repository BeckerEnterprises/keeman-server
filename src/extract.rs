//! Strict request extractors: JSON with content-type, size and
//! structure checks, and query strings without unknown parameters.

use std::collections::HashMap;

use axum::body::{Bytes, to_bytes};
use axum::extract::{FromRequest, Request};
use axum::http::header;
use serde::de::DeserializeOwned;
use serde_path_to_error::Segment;

use crate::error::{ApiError, ErrorCode};
use crate::types::{MESSAGE_PREFIX, MESSAGES, TOO_LARGE};

/// Default body limit.
pub const BODY_LIMIT: usize = 2 * 1024 * 1024;
/// Body limit of `batch` and rotation uploads.
pub const LARGE_BODY_LIMIT: usize = 16 * 1024 * 1024;

pub struct StrictJson<T>(pub T);

fn is_json_content_type(value: &str) -> bool {
    let mut parts = value.split(';').map(str::trim);
    let mime_ok = parts
        .next()
        .is_some_and(|m| m.eq_ignore_ascii_case("application/json"));
    mime_ok && parts.all(|p| p.eq_ignore_ascii_case("charset=utf-8"))
}

impl<T: DeserializeOwned, S: Send + Sync> FromRequest<S> for StrictJson<T> {
    type Rejection = ApiError;

    async fn from_request(request: Request, _state: &S) -> Result<Self, ApiError> {
        json(request).await.map(StrictJson)
    }
}

/// Reads a required JSON body: `415` → `413` → `400`.
pub async fn json<T: DeserializeOwned>(request: Request) -> Result<T, ApiError> {
    optional_json(request)
        .await?
        .ok_or_else(|| ApiError::pointer("", "request body required"))
}

/// Reads an optional JSON body; an empty body is `None`.
pub async fn optional_json<T: DeserializeOwned>(request: Request) -> Result<Option<T>, ApiError> {
    match json_bytes(request, BODY_LIMIT).await? {
        Some(bytes) => parse_json(&bytes).map(Some),
        None => Ok(None),
    }
}

/// The raw bytes of a JSON body up to `limit`: `415` → `413`.
/// An empty body is `None`.
pub async fn json_bytes(request: Request, limit: usize) -> Result<Option<Bytes>, ApiError> {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap_or(""));
    let json = content_type.is_some_and(is_json_content_type);
    if content_type.is_some() && !json {
        return Err(ApiError::new(ErrorCode::UnsupportedMediaType));
    }
    let bytes = to_bytes(request.into_body(), limit)
        .await
        .map_err(|_| ApiError::new(ErrorCode::PayloadTooLarge))?;
    if bytes.is_empty() {
        return Ok(None);
    }
    if !json {
        return Err(ApiError::new(ErrorCode::UnsupportedMediaType));
    }
    Ok(Some(bytes))
}

/// A binary body (`application/octet-stream`) up to `limit`:
/// another or missing content type is `415`, a larger body `413`.
pub async fn octet_stream(request: Request, limit: usize) -> Result<Bytes, ApiError> {
    let binary = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/octet-stream"));
    if !binary {
        return Err(ApiError::new(ErrorCode::UnsupportedMediaType));
    }
    to_bytes(request.into_body(), limit)
        .await
        .map_err(|_| ApiError::new(ErrorCode::PayloadTooLarge))
}

/// `deserialize_with` for optional fields: absent is `None`, `null` is an error.
pub fn present<'de, D: serde::Deserializer<'de>, T: serde::Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

/// Parses JSON into `T`; errors become one `errors[]` entry with a fixed text.
pub fn parse_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ApiError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = serde_path_to_error::deserialize(&mut deserializer).map_err(map_json_error)?;
    deserializer
        .end()
        .map_err(|_| ApiError::pointer("", "malformed JSON"))?;
    Ok(value)
}

fn map_json_error(error: serde_path_to_error::Error<serde_json::Error>) -> ApiError {
    let mut pointer = String::new();
    for segment in error.path().iter() {
        match segment {
            Segment::Seq { index } => pointer.push_str(&format!("/{index}")),
            Segment::Map { key } | Segment::Enum { variant: key } => {
                pointer.push('/');
                pointer.push_str(&key.replace('~', "~0").replace('/', "~1"));
            }
            Segment::Unknown => {}
        }
    }
    let inner = error.into_inner();
    if !inner.is_data() {
        return ApiError::pointer("", "malformed JSON");
    }
    let message = inner.to_string();
    if message.starts_with(TOO_LARGE) {
        return ApiError::new(ErrorCode::PayloadTooLarge);
    }
    if let Some(own) = message.strip_prefix(MESSAGE_PREFIX) {
        let detail = MESSAGES
            .iter()
            .copied()
            .find(|m| own.starts_with(m))
            .unwrap_or("invalid value");
        return ApiError::pointer(pointer, detail);
    }
    if let Some(field) = message
        .strip_prefix("missing field `")
        .and_then(|rest| rest.split('`').next())
    {
        // The field name comes from our own schema, not from the input.
        return ApiError::pointer(format!("{pointer}/{field}"), "missing field");
    }
    let detail = if message.starts_with("unknown field") {
        "unknown field"
    } else if message.starts_with("duplicate field") {
        "duplicate field"
    } else if message.starts_with("invalid type") {
        "invalid type"
    } else {
        "invalid value"
    };
    ApiError::pointer(pointer, detail)
}

/// Parses a query string that may only contain the given parameters, each once.
pub fn parse_query(
    query: Option<&str>,
    allowed: &[&'static str],
) -> Result<HashMap<&'static str, String>, ApiError> {
    let mut values = HashMap::new();
    for pair in query.unwrap_or("").split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let Some(name) = allowed.iter().copied().find(|a| *a == key) else {
            return Err(ApiError::parameter("query", "unknown query parameter"));
        };
        if values.insert(name, value.to_string()).is_some() {
            return Err(ApiError::parameter(name, "duplicate query parameter"));
        }
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::FieldError;
    use crate::types::{Device, KdfParamsInput};
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct Body {
        kdf: KdfParamsInput,
        device: Device,
    }

    fn field_error(json: &str) -> (ErrorCode, Option<FieldError>) {
        let error = parse_json::<Body>(json.as_bytes()).unwrap_err();
        let response = axum::response::IntoResponse::into_response(error);
        let problem = response
            .extensions()
            .get::<crate::error::ProblemData>()
            .cloned()
            .unwrap();
        (problem.code, problem.errors.into_iter().next())
    }

    const DEVICE: &str = r#""device":{"name":"x","client_type":"web"}"#;

    #[test]
    fn maps_errors_to_pointers_with_fixed_texts() {
        let (_, e) = field_error(&format!(r#"{{"kdf":{{"alg":"a","ops":1}},{DEVICE}}}"#));
        assert_eq!(
            e,
            Some(FieldError::Pointer {
                pointer: "/kdf/mem".into(),
                detail: "missing field"
            })
        );
        let (_, e) = field_error(&format!(
            r#"{{"kdf":{{"alg":"a","ops":1,"mem":2,"secret":"x"}},{DEVICE}}}"#
        ));
        assert_eq!(
            e,
            Some(FieldError::Pointer {
                pointer: "/kdf/secret".into(),
                detail: "unknown field"
            })
        );
        let (_, e) = field_error(r#"{"kdf":{"alg":"a","ops":"1","mem":2}}"#);
        assert_eq!(
            e,
            Some(FieldError::Pointer {
                pointer: "/kdf/ops".into(),
                detail: "invalid type"
            })
        );
        let (_, e) = field_error(
            r#"{"kdf":{"alg":"a","ops":1,"mem":2},"device":{"name":"","client_type":"web"}}"#,
        );
        assert_eq!(
            e,
            Some(FieldError::Pointer {
                pointer: "/device/name".into(),
                detail: "invalid device name"
            })
        );
        let (_, e) = field_error("{");
        assert_eq!(
            e,
            Some(FieldError::Pointer {
                pointer: "".into(),
                detail: "malformed JSON"
            })
        );
        let (_, e) = field_error(&format!(
            r#"{{"kdf":{{"alg":"a","ops":1,"mem":2}},{DEVICE}}} x"#
        ));
        assert_eq!(
            e,
            Some(FieldError::Pointer {
                pointer: "".into(),
                detail: "malformed JSON"
            })
        );
    }

    #[test]
    fn content_types() {
        assert!(is_json_content_type("application/json"));
        assert!(is_json_content_type("Application/JSON; charset=UTF-8"));
        assert!(!is_json_content_type("application/merge-patch+json"));
        assert!(!is_json_content_type("application/json; charset=latin1"));
        assert!(!is_json_content_type("text/plain"));
    }

    #[test]
    fn query_strings_are_strict() {
        assert_eq!(
            parse_query(Some("scope=others"), &["scope"]).unwrap()["scope"],
            "others"
        );
        assert!(parse_query(Some("scope=a&scope=b"), &["scope"]).is_err());
        assert!(parse_query(Some("other=1"), &["scope"]).is_err());
        assert!(parse_query(None, &["scope"]).unwrap().is_empty());
    }
}
